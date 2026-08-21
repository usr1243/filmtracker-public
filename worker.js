// Filmtracker API — Cloudflare Worker + KV (öffentliche Multi-User-Version mit Login)
// Jeder Account hat sein eigenes Daten-Blob im KV-Namespace FILM_STATE unter dem Key "state:<username>".
// Auth: Username+Passwort (PBKDF2 via Web Crypto), Session als signiertes HttpOnly-Cookie (HMAC-SHA256,
// kein serverseitiger Session-State nötig). Bewusst kein Email-Login/-Reset — kein externer
// Mail-Dienst nötig, wer das Passwort vergisst legt einen neuen Account an.

const RATINGS = ["LOVE", "LIKE", "MEH", "DISLIKE", "QUEUE"];
const STATUSES = ["Nachgeschaut", "Noch nicht geschaut"];

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const jsonCookie = (data, status, cookie) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "set-cookie": cookie,
    },
  });

/* ============================================================
   Auth-Helfer: Passwort-Hashing (PBKDF2), Session-Cookie (HMAC),
   Cookie-Parsing — alles über Web Crypto API (Worker-Runtime hat
   kein Node.js, also kein bcrypt/argon2, aber crypto.subtle reicht).
   ============================================================ */

const enc = new TextEncoder();
const dec = new TextDecoder();

function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64Url(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Konstante-Zeit-Vergleich — verhindert Timing-Angriffe auf Passwort-/Signatur-Vergleiche.
// Nie stattdessen === oder Array.every verwenden (die brechen beim ersten Unterschied ab).
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

const PBKDF2_ITERATIONS = 100000;

async function derivePbkdf2(password, saltBytes) {
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function makePasswordHash(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePbkdf2(password, salt);
  return { hash: toBase64Url(hash), salt: toBase64Url(salt) };
}

async function verifyPassword(password, storedHashB64, storedSaltB64) {
  const hash = await derivePbkdf2(password, fromBase64Url(storedSaltB64));
  return timingSafeEqual(hash, fromBase64Url(storedHashB64));
}

// Fester Decoy für den Login-Vergleich bei unbekanntem Username, damit die Antwortzeit
// nicht verrät, ob der Account existiert (siehe /api/login).
const DUMMY_SALT = toBase64Url(new Uint8Array(16));
const DUMMY_HASH = toBase64Url(new Uint8Array(32).fill(7));

async function hmacSign(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return toBase64Url(new Uint8Array(sig));
}

const SESSION_MAX_AGE = 60 * 60 * 24 * 30; // 30 Tage

async function makeSessionCookie(env, username) {
  const payload = { u: username, exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE };
  const payloadB64 = toBase64Url(enc.encode(JSON.stringify(payload)));
  const sig = await hmacSign(env.SESSION_SECRET, payloadB64);
  return `session=${payloadB64}.${sig}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_MAX_AGE}`;
}

const CLEAR_SESSION_COOKIE = "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// Prüft das Session-Cookie, gibt den (lowercased) Username zurück oder null.
async function verifySession(request, env) {
  const raw = parseCookies(request).session;
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot === -1) return null;
  const payloadB64 = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expectedSig = await hmacSign(env.SESSION_SECRET, payloadB64);
  if (!timingSafeEqual(enc.encode(sig), enc.encode(expectedSig))) return null;
  let payload;
  try { payload = JSON.parse(dec.decode(fromBase64Url(payloadB64))); } catch { return null; }
  if (!payload.u || !payload.exp || Math.floor(Date.now() / 1000) > payload.exp) return null;
  return payload.u;
}

/* ---------- KV-basiertes Rate-Limiting (in-memory würde in Workers nicht zuverlässig
   über Requests hinweg bestehen bleiben — deshalb KV-Counter mit expirationTtl). ---------- */

async function getLimitCount(env, key) {
  const raw = await env.FILM_STATE.get(key);
  return raw ? Number(raw) : 0;
}
async function bumpLimit(env, key, windowSeconds) {
  const count = await getLimitCount(env, key);
  await env.FILM_STATE.put(key, String(count + 1), { expirationTtl: windowSeconds });
}
// Prüft UND erhöht in einem Schritt — für Aktionen, bei denen jeder Versuch zählt (Register).
async function checkAndBump(env, key, limit, windowSeconds) {
  const count = await getLimitCount(env, key);
  if (count >= limit) return false;
  await env.FILM_STATE.put(key, String(count + 1), { expirationTtl: windowSeconds });
  return true;
}

const USERNAME_RE = /^[a-zA-Z0-9_]{3,24}$/;

/* ---------- Pro-User-State (statt fixem globalem Key wie in der privaten Version) ---------- */

async function loadState(env, userId) {
  const raw = await env.FILM_STATE.get("state:" + userId);
  const state = raw ? JSON.parse(raw) : { movies: [], nextId: 1 };
  state.lists = state.lists || [];
  state.nextListId = state.nextListId || 1;
  return state;
}
const saveState = (env, userId, state) => env.FILM_STATE.put("state:" + userId, JSON.stringify(state));

function cleanMovie(input, id, validListIds) {
  return {
    id,
    title: String(input.title || "").trim().slice(0, 300),
    rating: RATINGS.includes(input.rating) ? input.rating : "QUEUE",
    status: STATUSES.includes(input.status) ? input.status : "Noch nicht geschaut",
    updated: new Date().toISOString().slice(0, 19).replace("T", " "),
    comment: String(input.comment || "").slice(0, 2000),
    genre: String(input.genre || "").slice(0, 200),
    overview: String(input.overview || "").slice(0, 2000),
    poster: String(input.poster || "").slice(0, 200),
    year: String(input.year || "").slice(0, 4),
    enriched: !!input.enriched,
    lists: Array.isArray(input.lists)
      ? [...new Set(input.lists.map(Number).filter((n) => Number.isInteger(n) && (!validListIds || validListIds.has(n))))].slice(0, 50)
      : [],
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);

    const ip = request.headers.get("CF-Connecting-IP") || "unknown";

    try {
      /* ==================== Auth-Routen (kein Login nötig) ==================== */

      // POST /api/register — { username, password } -> Account anlegen + direkt einloggen
      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        if (!USERNAME_RE.test(username)) return json({ error: "Username muss 3-24 Zeichen sein (Buchstaben, Zahlen, _)" }, 400);
        if (password.length < 8) return json({ error: "Passwort muss mindestens 8 Zeichen haben" }, 400);
        if (!(await checkAndBump(env, "ratelimit:register:" + ip, 5, 3600))) {
          return json({ error: "Zu viele Registrierungen, bitte später erneut versuchen." }, 429);
        }

        const userLc = username.toLowerCase();
        if (await env.FILM_STATE.get("user:" + userLc)) return json({ error: "Username bereits vergeben" }, 409);

        // Reihenfolge bewusst so: state zuerst, dann user zuletzt — falls mittendrin was
        // schiefgeht, bleibt höchstens ein verwaistes leeres state:-Blob übrig (harmlos),
        // nie ein user-Eintrag ohne zugehörigen State.
        const { hash, salt } = await makePasswordHash(password);
        await saveState(env, userLc, { movies: [], nextId: 1, lists: [], nextListId: 1 });
        await env.FILM_STATE.put(
          "user:" + userLc,
          JSON.stringify({
            username,
            passwordHash: hash, salt, iterations: PBKDF2_ITERATIONS,
            createdAt: new Date().toISOString(),
          })
        );

        const cookie = await makeSessionCookie(env, userLc);
        return jsonCookie({ username }, 201, cookie);
      }

      // POST /api/login — { username, password }
      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");
        const userLc = username.toLowerCase();
        const limitKey = "ratelimit:login:" + userLc + ":" + ip;

        if ((await getLimitCount(env, limitKey)) >= 5) {
          return json({ error: "Zu viele Versuche, bitte in 15 Minuten erneut versuchen." }, 429);
        }

        const raw = await env.FILM_STATE.get("user:" + userLc);
        const user = raw ? JSON.parse(raw) : null;
        // Läuft IMMER durch verifyPassword (auch bei unbekanntem Username, gegen einen festen
        // Decoy-Hash) — sonst würde ein fehlender KV-Lookup die Antwort messbar schneller machen
        // und verraten, dass der Account gar nicht existiert.
        const target = user || { passwordHash: DUMMY_HASH, salt: DUMMY_SALT };
        const passOk = await verifyPassword(password, target.passwordHash, target.salt);
        const ok = !!user && passOk;

        if (!ok) {
          await bumpLimit(env, limitKey, 900);
          return json({ error: "Ungültige Anmeldedaten" }, 401);
        }
        await env.FILM_STATE.delete(limitKey);
        const cookie = await makeSessionCookie(env, userLc);
        return jsonCookie({ username: user.username }, 200, cookie);
      }

      // POST /api/logout
      if (path === "/api/logout" && request.method === "POST") {
        return jsonCookie({ ok: true }, 200, CLEAR_SESSION_COOKIE);
      }

      // GET /api/me — liefert eingeloggten Username oder 401 (Frontend-Bootstrap nutzt das)
      if (path === "/api/me" && request.method === "GET") {
        const userId = await verifySession(request, env);
        return userId ? json({ username: userId }) : json({ error: "not_authenticated" }, 401);
      }

      /* ==================== Ab hier: Login erforderlich ==================== */

      const userId = await verifySession(request, env);
      if (!userId) return json({ error: "not_authenticated" }, 401);

      // GET /api/state — kompletter Datenbestand (nur Filme, keine internen Felder)
      if (path === "/api/state" && request.method === "GET") {
        const state = await loadState(env, userId);
        return json({ movies: state.movies, nextId: state.nextId, lists: state.lists });
      }

      // POST /api/movies — neuen Film anlegen
      if (path === "/api/movies" && request.method === "POST") {
        const body = await request.json();
        if (!String(body.title || "").trim()) return json({ error: "Titel fehlt" }, 400);
        const state = await loadState(env, userId);
        const movie = cleanMovie(body, state.nextId++, new Set(state.lists.map((l) => l.id)));
        state.movies.push(movie);
        await saveState(env, userId, state);
        return json(movie, 201);
      }

      // PUT/DELETE /api/movies/:id
      const idMatch = path.match(/^\/api\/movies\/(\d+)$/);
      if (idMatch) {
        const id = Number(idMatch[1]);
        const state = await loadState(env, userId);
        const idx = state.movies.findIndex((m) => m.id === id);
        if (idx === -1) return json({ error: "Film nicht gefunden" }, 404);

        if (request.method === "DELETE") {
          state.movies.splice(idx, 1);
          await saveState(env, userId, state);
          return json({ ok: true });
        }
        if (request.method === "PUT") {
          const body = await request.json();
          const old = state.movies[idx];
          const merged = cleanMovie({ ...old, ...body }, id, new Set(state.lists.map((l) => l.id)));
          state.movies[idx] = merged;
          await saveState(env, userId, state);
          return json(merged);
        }
      }

      // POST /api/lists — { name } -> neue Liste
      if (path === "/api/lists" && request.method === "POST") {
        const body = await request.json();
        const name = String(body.name || "").trim().slice(0, 100);
        if (!name) return json({ error: "Name fehlt" }, 400);
        const state = await loadState(env, userId);
        const list = { id: state.nextListId++, name };
        state.lists.push(list);
        await saveState(env, userId, state);
        return json(list, 201);
      }

      // PUT/DELETE /api/lists/:id — umbenennen bzw. löschen (löscht nur die Zuordnung, keine Filme)
      const listMatch = path.match(/^\/api\/lists\/(\d+)$/);
      if (listMatch) {
        const id = Number(listMatch[1]);
        const state = await loadState(env, userId);
        const idx = state.lists.findIndex((l) => l.id === id);
        if (idx === -1) return json({ error: "Liste nicht gefunden" }, 404);

        if (request.method === "DELETE") {
          state.lists.splice(idx, 1);
          for (const m of state.movies) if (Array.isArray(m.lists)) m.lists = m.lists.filter((lid) => lid !== id);
          await saveState(env, userId, state);
          return json({ ok: true });
        }
        if (request.method === "PUT") {
          const body = await request.json();
          const name = String(body.name || "").trim().slice(0, 100);
          if (!name) return json({ error: "Name fehlt" }, 400);
          state.lists[idx].name = name;
          await saveState(env, userId, state);
          return json(state.lists[idx]);
        }
      }

      // POST /api/import — { movies: [...], mode: "merge" | "replace" }
      // merge: gleicht per Titel ab (Groß/Klein egal), aktualisiert Bewertung/Status/Kommentar,
      //        legt unbekannte Titel neu an, löscht nichts. replace: ersetzt alles.
      if (path === "/api/import" && request.method === "POST") {
        const body = await request.json();
        if (!Array.isArray(body.movies)) return json({ error: "movies fehlt" }, 400);
        const state = await loadState(env, userId);
        let added = 0, updated = 0;

        if (body.mode === "replace") {
          state.movies = [];
          state.nextId = 1;
        }
        const validListIds = new Set(state.lists.map((l) => l.id));
        // replace: alle Zeilen 1:1 übernehmen (gleiche Titel = z.B. Remakes bleiben getrennt)
        // merge: per Titel abgleichen, nichts löschen
        const byTitle = new Map(state.movies.map((m) => [m.title.toLowerCase(), m]));
        for (const raw of body.movies) {
          const title = String(raw.title || "").trim();
          if (!title) continue;
          const existing = body.mode === "replace" ? null : byTitle.get(title.toLowerCase());
          if (existing) {
            if (raw.rating && RATINGS.includes(raw.rating)) existing.rating = raw.rating;
            if (raw.status && STATUSES.includes(raw.status)) existing.status = raw.status;
            if (raw.comment) existing.comment = String(raw.comment).slice(0, 2000);
            if (Array.isArray(raw.lists) && raw.lists.length) {
              const add = raw.lists.map(Number).filter((n) => validListIds.has(n));
              existing.lists = [...new Set([...(existing.lists || []), ...add])];
            }
            updated++;
          } else {
            const movie = cleanMovie(raw, state.nextId++, validListIds);
            if (raw.updated) movie.updated = String(raw.updated).slice(0, 30);
            state.movies.push(movie);
            byTitle.set(title.toLowerCase(), movie);
            added++;
          }
        }
        await saveState(env, userId, state);
        return json({ ok: true, added, updated, total: state.movies.length });
      }

      // Genre-Namen für eine Liste TMDb-Genre-IDs (Liste wird im State gecacht — jetzt pro User,
      // nicht mehr global; unkritisch, es sind nur ~40 Genre-Namen, das Duplizieren pro Account kostet nichts).
      async function genreNames(state, ids) {
        if (!state.genreCache) {
          const [gm, gt] = await Promise.all([
            fetch("https://api.themoviedb.org/3/genre/movie/list?language=de-DE&api_key=" + env.TMDB_KEY).then((r) => r.json()),
            fetch("https://api.themoviedb.org/3/genre/tv/list?language=de-DE&api_key=" + env.TMDB_KEY).then((r) => r.json()),
          ]);
          state.genreCache = {};
          for (const g of [...(gm.genres || []), ...(gt.genres || [])]) state.genreCache[g.id] = g.name;
        }
        return (ids || []).map((id) => state.genreCache[id]).filter(Boolean).join(", ");
      }

      // Bester Treffer für einen Titel. Verhindert, dass bei mehrdeutigen Titeln (Remakes,
      // gleichnamige alte Filme, andere Sprachversionen) ein zufälliger/unpassender Treffer
      // genommen wird. Verfahren (jede Stufe nur falls die vorige nichts Eindeutiges liefert):
      //   1. Titel exakt getroffen (Titel ODER Originaltitel, wegen deutscher Lokalisierung
      //      wie "Riddick - Chroniken eines Kriegers" für "The Chronicles of Riddick") —
      //      gewinnt, außer ein Teiltreffer hat >20x mehr Stimmen (echtes Bekanntheitssignal,
      //      `popularity` ist zu tagesaktuell/volatil für diesen Zweck).
      //   2. Bester Teiltreffer (Substring in beide Richtungen, mind. 4 Zeichen Query-Länge).
      //   3. Fallback: meiste Stimmen unter allen Treffern.
      // Nicht-lateinische Titel (z.B. Koreanisch) normalisieren zu "" — müssen ausgeschlossen
      // werden, sonst ist "" trivial Teilstring von allem und erzeugt Fehltreffer.
      function bestMatch(results, title) {
        const norm = (s) => String(s || "").replace(/[^a-z0-9]/gi, "").toLowerCase();
        const q = norm(title);
        const candidates = (results || []).filter((r) => r.media_type === "movie" || r.media_type === "tv");
        if (!candidates.length) return null;
        const namesOf = (r) => [r.title, r.name, r.original_title, r.original_name].filter(Boolean).map(norm).filter(Boolean);
        const votes = (r) => r.vote_count || 0;
        const isExact = (r) => namesOf(r).some((n) => n === q);
        const isNear = (r) => q.length >= 4 && namesOf(r).some((n) => q.includes(n) || n.includes(q));
        const maxBy = (arr, fn) => arr.reduce((best, r) => (fn(r) > fn(best) ? r : best), arr[0]);
        const exact = candidates.filter(isExact);
        const near = candidates.filter(isNear);
        const bestExact = exact.length ? maxBy(exact, votes) : null;
        const bestNear = near.length ? maxBy(near, votes) : null;
        if (bestExact && votes(bestExact) > 0 && votes(bestExact) * 20 >= votes(bestNear || {})) return bestExact;
        if (bestNear) return bestNear;
        return maxBy(candidates, votes);
      }

      // Einen Film via TMDb anreichern (mutiert das Objekt). true = Treffer, false = kein Treffer.
      async function enrichMovie(state, movie) {
        const res = await fetch(
          "https://api.themoviedb.org/3/search/multi?language=de-DE&query=" +
            encodeURIComponent(movie.title) + "&api_key=" + env.TMDB_KEY
        );
        if (!res.ok) throw new Error("TMDb-Fehler " + res.status);
        const data = await res.json();
        const hit = bestMatch(data.results, movie.title);
        if (!hit) return false;
        movie.genre = await genreNames(state, hit.genre_ids);
        movie.overview = String(hit.overview || "").slice(0, 2000);
        movie.poster = hit.poster_path || "";
        movie.year = (hit.release_date || hit.first_air_date || "").slice(0, 4);
        return true;
      }

      // POST /api/enrich/:id — einen Film anreichern
      const enrichMatch = path.match(/^\/api\/enrich\/(\d+)$/);
      if (enrichMatch && request.method === "POST") {
        const state = await loadState(env, userId);
        const movie = state.movies.find((m) => m.id === Number(enrichMatch[1]));
        if (!movie) return json({ error: "Film nicht gefunden" }, 404);
        let found = false;
        try { found = await enrichMovie(state, movie); } finally { movie.enriched = true; }
        await saveState(env, userId, state);
        return found ? json({ ok: true, movie }) : json({ ok: false, notFound: true, title: movie.title });
      }

      // POST /api/enrich-batch — verarbeitet die nächsten fehlenden Filme (bounded, wegen Worker-Subrequest-Limit)
      // Antwort sagt, wie viele noch übrig sind → Client ruft solange auf, bis remaining = 0.
      // ?force=1 → ignoriert `enriched` und läuft über ALLE Filme (Re-Match mit verbessertem Algorithmus).
      // ?offset=N → Fortsetzungspunkt bei force-Läufen (batch-weise, da Worker-Subrequest-Limit).
      if (path === "/api/enrich-batch" && request.method === "POST") {
        const state = await loadState(env, userId);
        const force = url.searchParams.get("force") === "1";
        const offset = Number(url.searchParams.get("offset") || 0);
        const pending = force ? state.movies.slice(offset) : state.movies.filter((m) => !m.enriched);
        const batch = pending.slice(0, 25);
        let done = 0, notFound = 0;
        const changes = [];
        for (const movie of batch) {
          const before = { genre: movie.genre, overview: movie.overview, poster: movie.poster, year: movie.year };
          try { (await enrichMovie(state, movie)) ? done++ : notFound++; }
          catch { notFound++; }
          movie.enriched = true; // auch bei "kein Treffer" markieren, sonst Endlosschleife
          if (force && (before.poster !== movie.poster || before.overview !== movie.overview)) {
            changes.push({ id: movie.id, title: movie.title, before, after: { genre: movie.genre, overview: movie.overview, poster: movie.poster, year: movie.year } });
          }
        }
        await saveState(env, userId, state);
        const remaining = force ? pending.length - batch.length : pending.length - batch.length;
        return json({ ok: true, done, notFound, processed: batch.length, remaining, nextOffset: offset + batch.length, changes });
      }

      // GET /api/search?q= — durchsucht die TMDb-Bibliothek (Key bleibt server-seitig).
      // Liefert Kandidaten zum Hinzufügen; markiert, was schon in der eigenen Liste ist.
      if (path === "/api/search" && request.method === "GET") {
        const q = (url.searchParams.get("q") || "").trim();
        if (q.length < 2) return json({ results: [] });
        const state = await loadState(env, userId);
        const res = await fetch(
          "https://api.themoviedb.org/3/search/multi?language=de-DE&include_adult=false&query=" +
            encodeURIComponent(q) + "&api_key=" + env.TMDB_KEY
        );
        if (!res.ok) return json({ error: "TMDb-Fehler " + res.status }, 502);
        const data = await res.json();
        const owned = new Set(state.movies.map((m) => m.title.trim().toLowerCase()));
        const results = [];
        for (const r of (data.results || [])) {
          if (r.media_type !== "movie" && r.media_type !== "tv") continue;
          const title = r.title || r.name || "";
          if (!title) continue;
          // Gegen alle Titel-Varianten prüfen (nicht nur den lokalisierten Titel) — TMDb liefert bei
          // language=de-DE oft einen deutschen Titel ("Der Soldat James Ryan"), die Bibliothek speichert
          // aber meist den englischen ("Saving Private Ryan"). Ohne original_title/-name würde das als
          // "nicht in Liste" durchrutschen, obwohl der Film längst vorhanden ist.
          const variants = [r.title, r.name, r.original_title, r.original_name]
            .filter(Boolean).map((t) => t.trim().toLowerCase());
          results.push({
            title,
            year: (r.release_date || r.first_air_date || "").slice(0, 4),
            poster: r.poster_path || "",
            overview: String(r.overview || "").slice(0, 2000),
            genre: await genreNames(state, r.genre_ids),
            mediaType: r.media_type,
            popularity: r.popularity || 0,
            inLibrary: variants.some((v) => owned.has(v)),
          });
          if (results.length >= 16) break;
        }
        // Neueste zuerst, älteste zuletzt (unbekanntes Jahr zählt als ältestes).
        results.sort((a, b) => (b.year || "0").localeCompare(a.year || "0"));
        return json({ results });
      }

      // POST /api/ai-import — { text } -> Groq extrahiert Filmtitel aus Freitext,
      // pro Titel wird per bestMatch() der beste TMDb-Treffer gesucht (gleiche
      // Matching-Logik wie überall sonst). Schreibt nichts in KV (read-only,
      // wie /api/search) — die eigentliche Übernahme läuft über bestehende
      // Endpoints (/api/import, PUT /api/movies/:id), siehe Frontend.
      if (path === "/api/ai-import" && request.method === "POST") {
        const body = await request.json();
        const text = String(body.text || "").trim().slice(0, 8000);
        if (!text) return json({ error: "Text fehlt" }, 400);
        if (!env.GROQ_API_KEY) return json({ error: "GROQ_API_KEY nicht konfiguriert" }, 500);

        const groqRes = await fetch("https://api.groq.com/openai/v1/chat/completions", {
          method: "POST",
          headers: { "content-type": "application/json", authorization: "Bearer " + env.GROQ_API_KEY },
          body: JSON.stringify({
            model: "openai/gpt-oss-120b",
            response_format: { type: "json_object" },
            temperature: 0,
            messages: [
              {
                role: "system",
                content:
                  'Du bist ein striktes Extraktionswerkzeug. Finde alle Film-/Serientitel im Text (Freitext, Liste oder Tabelle, egal). Falls im Text zu einem Titel eine Notiz, Begründung, Einordnung oder ein Kommentar steht (z.B. eine Tabellenspalte wie "Warum behalten?", ein Fließtext-Kommentar dahinter), übernimm diese als kurze Notiz. Antworte NUR mit JSON der Form {"items":[{"title":"...","note":"..."}]} — dedupliziert nach Titel, getrimmt, Original-Schreibweise. "note" ist "" wenn im Text nichts Entsprechendes steht, keine Erklärungen erfinden.',
              },
              { role: "user", content: text },
            ],
          }),
        });
        if (!groqRes.ok) return json({ error: "Groq-Fehler " + groqRes.status }, 502);
        const groqData = await groqRes.json();

        let items = [];
        try {
          const raw = (groqData.choices?.[0]?.message?.content || "{}").trim().replace(/^```json\s*|```$/g, "");
          const parsed = JSON.parse(raw);
          items = Array.isArray(parsed.items)
            ? parsed.items.map((it) => ({ title: String(it?.title || "").trim(), note: String(it?.note || "").trim().slice(0, 2000) })).filter((it) => it.title)
            : [];
        } catch {
          return json({ error: "Konnte KI-Antwort nicht lesen" }, 502);
        }

        // nach Titel dedupliziert (case-insensitiv), erste gefundene Notiz gewinnt
        const byTitle = new Map();
        for (const it of items) {
          const key = it.title.toLowerCase();
          if (!byTitle.has(key)) byTitle.set(key, it);
        }
        const uniq = [...byTitle.values()];
        // Cap bei 30, um mit Puffer unter dem Cloudflare-Subrequest-Limit (Free-Plan ~50) zu bleiben:
        // 1 Groq-Call + max. 2 Genre-Calls (kalter Cache) + bis zu 30 TMDb-Search-Calls.
        const truncated = uniq.length > 30;
        const capped = uniq.slice(0, 30);

        const state = await loadState(env, userId);
        const owned = new Map(state.movies.map((m) => [m.title.trim().toLowerCase(), m]));
        const suggestions = [];
        for (let i = 0; i < capped.length; i += 5) {
          // 5er-Chunks statt sequenziell, kürzere Wall-Clock-Zeit bei größeren Pasten
          const chunk = capped.slice(i, i + 5);
          const results = await Promise.all(
            chunk.map(async ({ title, note }) => {
              try {
                const res = await fetch(
                  "https://api.themoviedb.org/3/search/multi?language=de-DE&query=" +
                    encodeURIComponent(title) + "&api_key=" + env.TMDB_KEY
                );
                const data = res.ok ? await res.json() : { results: [] };
                const hit = bestMatch(data.results, title);
                if (!hit) {
                  return { queryTitle: title, matched: false, title, year: "", poster: "", overview: "", genre: "", mediaType: "", existingId: null, note };
                }
                // Gegen alle Titel-Varianten des TMDb-Treffers prüfen, ob der Film schon in der
                // Bibliothek ist — sonst würde ein Merge-Import Rating/Status eines bereits
                // bewerteten Films versehentlich auf den Batch-Default zurücksetzen.
                const variants = [hit.title, hit.name, hit.original_title, hit.original_name]
                  .filter(Boolean).map((t) => t.trim().toLowerCase());
                const existing = variants.map((v) => owned.get(v)).find(Boolean);
                return {
                  queryTitle: title, matched: true,
                  title: hit.title || hit.name || title,
                  year: (hit.release_date || hit.first_air_date || "").slice(0, 4),
                  poster: hit.poster_path || "",
                  overview: String(hit.overview || "").slice(0, 2000),
                  genre: await genreNames(state, hit.genre_ids),
                  mediaType: hit.media_type,
                  existingId: existing ? existing.id : null,
                  note,
                };
              } catch {
                return { queryTitle: title, matched: false, title, year: "", poster: "", overview: "", genre: "", mediaType: "", existingId: null, note };
              }
            })
          );
          suggestions.push(...results);
        }
        return json({ suggestions, truncated, extractedCount: uniq.length });
      }

      return json({ error: "Unbekannter Endpoint" }, 404);
    } catch (e) {
      return json({ error: String(e.message || e) }, 500);
    }
  },
};
