import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const STATE_FILE = path.join(DATA_DIR, 'athlete-state.json');
const ONLINE_DB_FILE = path.join(DATA_DIR, 'online-db.json');
const SECRET_FILE = path.join(DATA_DIR, 'auth-secret.txt');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function getAuthSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  return 'ringfuel-pro-cloud-hmac-v9-team-giron';
}

const AUTH_SECRET = getAuthSecret();

function createInitialOnlineDb() {
  const now = new Date().toISOString();
  return {
    users: {},
    gyms: {
      'TEAM-GIRON': {
        code: 'TEAM-GIRON',
        name: 'Team Girón · Sala Oficial de Boxeo',
        weeklyGoalKm: 90,
        coachMessage:
          'Jueves: Sparring oficial. Mantener hidratación electrolítica, sueño 7.5h+ y peso controlado toda la semana.',
        createdBy: 'system',
        createdAt: now,
        feed: [
          {
            id: 'post_welcome_1',
            userId: 'system',
            authorName: 'Esquina Oficial · RINGFUEL PRO',
            weightInfo: 'Sala Activa',
            type: 'challenge',
            badge: '🏆 Sala Inaugurada',
            text: '¡Bienvenidos a la Sala Online TEAM-GIRON! Regístrense con su correo y contraseña para sincronizar automáticamente sus kilómetros, rondas de sparring, dieta y posición en el Ranking Libra por Libra.',
            createdAt: now,
            reactions: { gloves: [], fire: [], trophy: [] },
          },
        ],
      },
    },
  };
}

function loadOnlineDb() {
  try {
    if (fs.existsSync(ONLINE_DB_FILE)) {
      const parsed = JSON.parse(fs.readFileSync(ONLINE_DB_FILE, 'utf-8'));
      if (parsed && parsed.users && parsed.gyms) {
        if (!parsed.gyms['TEAM-GIRON']) {
          parsed.gyms['TEAM-GIRON'] = createInitialOnlineDb().gyms['TEAM-GIRON'];
        }
        return parsed;
      }
    }
  } catch (err) {
    console.error('Error reading online-db.json:', err.message);
  }
  const fresh = createInitialOnlineDb();
  saveOnlineDb(fresh);
  return fresh;
}

function saveOnlineDb(db) {
  const tmp = `${ONLINE_DB_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), 'utf-8');
  fs.renameSync(tmp, ONLINE_DB_FILE);
}

let onlineDb = loadOnlineDb();

// Password hashing & token signing using built-in node:crypto
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, expectedHash) {
  try {
    const hashBuf = Buffer.from(
      crypto.scryptSync(String(password), salt, 64).toString('hex'),
      'hex'
    );
    const expectedBuf = Buffer.from(expectedHash, 'hex');
    if (hashBuf.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(hashBuf, expectedBuf);
  } catch {
    return false;
  }
}

function signToken(payload) {
  const data = Buffer.from(
    JSON.stringify({
      ...payload,
      iat: Date.now(),
      exp: Date.now() + 1000 * 60 * 60 * 24 * 60, // 60 days
    })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', AUTH_SECRET).update(data).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf-8'));
    if (parsed.exp && Date.now() > parsed.exp) return null;
    return parsed;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  const decoded = verifyToken(token);
  if (!decoded || !decoded.uid) {
    return res.status(401).json({ error: 'Sesión inválida o expirada. Inicia sesión nuevamente.' });
  }
  // Auto-rehydrate user entry if free-tier cloud container recycled
  if (!onlineDb.users[decoded.uid] && decoded.email) {
    const now = new Date().toISOString();
    onlineDb.users[decoded.uid] = {
      id: decoded.uid,
      email: decoded.email,
      name: decoded.name || 'Boxeador',
      passwordHash: decoded.ph || '',
      salt: decoded.ps || '',
      gymCode: normalizeGymCode(decoded.gymCode || 'TEAM-GIRON'),
      athleteState: null,
      summaryCard: null,
      createdAt: now,
      lastLoginAt: now,
      updatedAt: now,
    };
    saveOnlineDb(onlineDb);
  }
  if (!onlineDb.users[decoded.uid]) {
    return res.status(401).json({ error: 'Sesión inválida o expirada. Inicia sesión nuevamente.' });
  }
  req.authUser = onlineDb.users[decoded.uid];
  next();
}

function normalizeGymCode(raw) {
  const cleaned = String(raw || 'TEAM-GIRON')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 24);
  return cleaned || 'TEAM-GIRON';
}

function computeFallbackSummary(user) {
  const st = user.athleteState || {};
  const prof = st.profile || {};
  const card = user.summaryCard || {};

  const sevenAgo = new Date();
  sevenAgo.setDate(sevenAgo.getDate() - 7);
  const sevenIso = `${sevenAgo.getFullYear()}-${String(sevenAgo.getMonth() + 1).padStart(2, '0')}-${String(sevenAgo.getDate()).padStart(2, '0')}`;
  const runs = st.roadwork?.runs || [];
  const km7d =
    card.km7d !== undefined
      ? Number(card.km7d)
      : Number(
          runs
            .filter((r) => r.date >= sevenIso)
            .reduce((s, r) => s + Number(r.distanceKm || 0), 0)
            .toFixed(1)
        );

  const sparringLogs = st.cornerPro?.sparringLogs || [];
  const sparringRounds =
    card.sparringRounds !== undefined
      ? Number(card.sparringRounds)
      : sparringLogs.reduce((s, x) => s + Number(x.rounds || 0), 0);

  const mealsDone =
    card.mealsTodayDone !== undefined
      ? Number(card.mealsTodayDone)
      : Object.values(st.nutrition?.completedMealsToday || {}).filter(Boolean).length;

  const radarScore = Number(card.radarScore || 82);
  const p4pScore =
    card.p4pScore !== undefined
      ? Number(card.p4pScore)
      : Math.round(radarScore * 5 + km7d * 18 + sparringRounds * 12 + mealsDone * 15);

  return {
    userId: user.id,
    name: prof.name || user.name || 'Boxeador',
    sex: prof.sex || card.sex || 'M',
    currentWeight: Number(prof.currentWeight || card.currentWeight || 72),
    targetWeight: Number(prof.targetWeight || card.targetWeight || 75),
    tierShort: card.tierShort || `${prof.targetWeight || 75} kg`,
    radarScore,
    km7d,
    bestPace: card.bestPace || '--:--',
    sparringRounds,
    mealsTodayDone: mealsDone,
    pullups: Number(card.pullups ?? st.cornerPro?.physicalBenchmarks?.pullupsMax ?? 12),
    bag3m: Number(card.bag3m ?? st.cornerPro?.physicalBenchmarks?.bagPunches3Min ?? 210),
    p4pScore,
    updatedAt: user.updatedAt || user.lastLoginAt || user.createdAt,
  };
}

function buildGymSnapshot(gymCode) {
  const code = normalizeGymCode(gymCode);
  let gym = onlineDb.gyms[code];
  if (!gym) {
    gym = {
      code,
      name: `Sala de Boxeo · ${code}`,
      weeklyGoalKm: 80,
      coachMessage: 'Mantener constancia diaria en carrera, técnica y nutrición limpia.',
      createdBy: 'auto',
      createdAt: new Date().toISOString(),
      feed: [],
    };
    onlineDb.gyms[code] = gym;
    saveOnlineDb(onlineDb);
  }

  const members = Object.values(onlineDb.users)
    .filter((u) => normalizeGymCode(u.gymCode) === code)
    .map((u) => computeFallbackSummary(u))
    .sort((a, b) => b.p4pScore - a.p4pScore);

  const totalKm7d = Number(members.reduce((s, m) => s + Number(m.km7d || 0), 0).toFixed(1));
  const totalSparringRounds = members.reduce((s, m) => s + Number(m.sparringRounds || 0), 0);
  const goalKm = Math.max(10, Number(gym.weeklyGoalKm || 90));
  const goalProgressPct = Math.min(100, Math.round((totalKm7d / goalKm) * 100));

  return {
    code: gym.code,
    name: gym.name,
    weeklyGoalKm: goalKm,
    coachMessage: gym.coachMessage,
    members,
    teamStats: {
      activeBoxersCount: members.length,
      totalKm7d,
      totalSparringRounds,
      weeklyGoalKm: goalKm,
      goalProgressPct,
    },
    feed: (gym.feed || []).slice(0, 50),
  };
}

function sanitizeUser(u) {
  return {
    id: u.id,
    email: u.email,
    name: u.athleteState?.profile?.name || u.name,
    gymCode: normalizeGymCode(u.gymCode),
    createdAt: u.createdAt,
    updatedAt: u.updatedAt || u.createdAt,
  };
}

const app = express();

// Enable CORS so standalone files or external frontends can connect cleanly
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: '16mb' }));

// ============================================================================
// ONLINE CLOUD & MULTI-USER GYM ENDPOINTS (v9)
// ============================================================================

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    mode: 'ringfuel-online-cloud-v9',
    usersCount: Object.keys(onlineDb.users).length,
    gymsCount: Object.keys(onlineDb.gyms).length,
    serverTime: new Date().toISOString(),
  });
});

app.post('/api/auth/register', (req, res) => {
  try {
    const { email, password, name, gymCode, athleteState, summaryCard } = req.body || {};
    const cleanEmail = String(email || '').trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({ error: 'Ingresa un correo electrónico válido.' });
    }
    if (!password || String(password).length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
    }

    const existing = Object.values(onlineDb.users).find((u) => u.email === cleanEmail);
    if (existing) {
      return res.status(409).json({
        error: 'Ya existe una cuenta registrada con este correo. Usa «Iniciar Sesión».',
      });
    }

    const code = normalizeGymCode(gymCode || 'TEAM-GIRON');
    if (!onlineDb.gyms[code]) {
      onlineDb.gyms[code] = {
        code,
        name: code === 'TEAM-GIRON' ? 'Team Girón · Sala Oficial de Boxeo' : `Sala Oficial · ${code}`,
        weeklyGoalKm: 90,
        coachMessage: 'Disciplina diaria: carrera, hidratación y sparring inteligente.',
        createdBy: cleanEmail,
        createdAt: new Date().toISOString(),
        feed: [],
      };
    }

    const uid = `usr_${crypto.randomBytes(8).toString('hex')}`;
    const { salt, hash } = hashPassword(password);
    const now = new Date().toISOString();

    const cleanName = String(name || athleteState?.profile?.name || 'Boxeador').trim();
    const stateToStore = athleteState
      ? {
          ...athleteState,
          profile: {
            ...(athleteState.profile || {}),
            name: cleanName,
          },
        }
      : null;

    const newUser = {
      id: uid,
      email: cleanEmail,
      name: cleanName,
      passwordHash: hash,
      salt,
      gymCode: code,
      athleteState: stateToStore,
      summaryCard: summaryCard || null,
      createdAt: now,
      lastLoginAt: now,
      updatedAt: now,
    };

    onlineDb.users[uid] = newUser;

    const cw = stateToStore?.profile?.currentWeight || 72;
    const tw = stateToStore?.profile?.targetWeight || 75;
    onlineDb.gyms[code].feed.unshift({
      id: `post_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      userId: uid,
      authorName: cleanName,
      weightInfo: `${cw} → ${tw} kg`,
      type: 'join',
      badge: '🥊 Nuevo en la Sala',
      text: `${cleanName} se conectó a la sala online ${code} (${cw} kg → división ${tw} kg).`,
      createdAt: now,
      reactions: { gloves: [], fire: [], trophy: [] },
    });

    saveOnlineDb(onlineDb);

    const token = signToken({
      uid,
      email: cleanEmail,
      name: cleanName,
      gymCode: code,
      ph: hash,
      ps: salt,
    });
    return res.json({
      ok: true,
      token,
      user: sanitizeUser(newUser),
      athleteState: newUser.athleteState,
      gym: buildGymSnapshot(code),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body || {};
    const cleanEmail = String(email || '').trim().toLowerCase();
    const user = Object.values(onlineDb.users).find((u) => u.email === cleanEmail);
    if (!user || !verifyPassword(password || '', user.salt, user.passwordHash)) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    user.lastLoginAt = new Date().toISOString();
    saveOnlineDb(onlineDb);

    const token = signToken({
      uid: user.id,
      email: user.email,
      name: user.name,
      gymCode: user.gymCode,
      ph: user.passwordHash,
      ps: user.salt,
    });
    return res.json({
      ok: true,
      token,
      user: sanitizeUser(user),
      athleteState: user.athleteState,
      gym: buildGymSnapshot(user.gymCode),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = req.authUser;
  res.json({
    ok: true,
    user: sanitizeUser(user),
    athleteState: user.athleteState,
    gym: buildGymSnapshot(user.gymCode),
  });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const user = req.authUser;
  if (!verifyPassword(currentPassword || '', user.salt, user.passwordHash)) {
    return res.status(400).json({ error: 'La contraseña actual no coincide.' });
  }
  if (!newPassword || String(newPassword).length < 6) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener mínimo 6 caracteres.' });
  }
  const { salt, hash } = hashPassword(newPassword);
  user.salt = salt;
  user.passwordHash = hash;
  user.updatedAt = new Date().toISOString();
  saveOnlineDb(onlineDb);
  res.json({ ok: true, message: 'Contraseña actualizada correctamente.' });
});

app.put('/api/cloud/sync', requireAuth, (req, res) => {
  try {
    const { athleteState, summaryCard } = req.body || {};
    const user = req.authUser;
    if (athleteState && typeof athleteState === 'object') {
      user.athleteState = athleteState;
      if (athleteState.profile?.name) {
        user.name = athleteState.profile.name;
      }
    }
    if (summaryCard && typeof summaryCard === 'object') {
      user.summaryCard = summaryCard;
    }
    user.updatedAt = new Date().toISOString();
    saveOnlineDb(onlineDb);

    res.json({
      ok: true,
      syncedAt: user.updatedAt,
      user: sanitizeUser(user),
      gym: buildGymSnapshot(user.gymCode),
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/gym/:code', (req, res) => {
  try {
    const snapshot = buildGymSnapshot(req.params.code || 'TEAM-GIRON');
    res.json({ ok: true, gym: snapshot });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/gym/join', requireAuth, (req, res) => {
  try {
    const { gymCode, gymName, weeklyGoalKm } = req.body || {};
    const code = normalizeGymCode(gymCode);
    const user = req.authUser;
    if (!onlineDb.gyms[code]) {
      onlineDb.gyms[code] = {
        code,
        name: gymName ? String(gymName).trim().slice(0, 60) : `Sala Oficial · ${code}`,
        weeklyGoalKm: Number(weeklyGoalKm) || 90,
        coachMessage: 'Entrena fuerte, cuida el peso y apoya a tu esquina.',
        createdBy: user.id,
        createdAt: new Date().toISOString(),
        feed: [],
      };
    } else if (gymName && String(gymName).trim()) {
      onlineDb.gyms[code].name = String(gymName).trim().slice(0, 60);
    }

    const prevCode = user.gymCode;
    user.gymCode = code;
    user.updatedAt = new Date().toISOString();

    if (prevCode !== code) {
      const cw = user.athleteState?.profile?.currentWeight || 72;
      const tw = user.athleteState?.profile?.targetWeight || 75;
      onlineDb.gyms[code].feed.unshift({
        id: `post_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        userId: user.id,
        authorName: user.name,
        weightInfo: `${cw} → ${tw} kg`,
        type: 'join',
        badge: '🥊 Cambio de Sala',
        text: `${user.name} entró a la sala ${code}.`,
        createdAt: user.updatedAt,
        reactions: { gloves: [], fire: [], trophy: [] },
      });
    }

    saveOnlineDb(onlineDb);
    res.json({
      ok: true,
      user: sanitizeUser(user),
      gym: buildGymSnapshot(code),
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/gym/coach-notice', requireAuth, (req, res) => {
  try {
    const { coachMessage, weeklyGoalKm, gymName } = req.body || {};
    const code = normalizeGymCode(req.authUser.gymCode);
    const gym = onlineDb.gyms[code];
    if (!gym) return res.status(404).json({ error: 'Sala no encontrada' });

    if (typeof coachMessage === 'string' && coachMessage.trim()) {
      gym.coachMessage = coachMessage.trim().slice(0, 260);
    }
    if (weeklyGoalKm !== undefined && Number(weeklyGoalKm) >= 10) {
      gym.weeklyGoalKm = Math.min(2000, Number(weeklyGoalKm));
    }
    if (typeof gymName === 'string' && gymName.trim()) {
      gym.name = gymName.trim().slice(0, 60);
    }
    saveOnlineDb(onlineDb);
    res.json({ ok: true, gym: buildGymSnapshot(code) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/gym/post', requireAuth, (req, res) => {
  try {
    const { type = 'status', text, badge } = req.body || {};
    const cleanText = String(text || '').trim().slice(0, 320);
    if (!cleanText) {
      return res.status(400).json({ error: 'Escribe un mensaje o logro para publicar.' });
    }
    const user = req.authUser;
    const code = normalizeGymCode(user.gymCode);
    if (!onlineDb.gyms[code]) {
      buildGymSnapshot(code);
    }
    const cw = user.athleteState?.profile?.currentWeight || 72;
    const tw = user.athleteState?.profile?.targetWeight || 75;

    const post = {
      id: `post_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      userId: user.id,
      authorName: user.athleteState?.profile?.name || user.name,
      weightInfo: `${cw} → ${tw} kg`,
      type,
      badge: badge || '🥊 Esquina Activa',
      text: cleanText,
      createdAt: new Date().toISOString(),
      reactions: { gloves: [], fire: [], trophy: [] },
    };

    onlineDb.gyms[code].feed.unshift(post);
    if (onlineDb.gyms[code].feed.length > 80) {
      onlineDb.gyms[code].feed = onlineDb.gyms[code].feed.slice(0, 80);
    }
    saveOnlineDb(onlineDb);

    res.json({ ok: true, post, gym: buildGymSnapshot(code) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/gym/react', requireAuth, (req, res) => {
  try {
    const { postId, reaction = 'gloves' } = req.body || {};
    if (!['gloves', 'fire', 'trophy'].includes(reaction)) {
      return res.status(400).json({ error: 'Reacción no válida.' });
    }
    const user = req.authUser;
    const code = normalizeGymCode(user.gymCode);
    const gym = onlineDb.gyms[code];
    if (!gym) return res.status(404).json({ error: 'Sala no encontrada.' });

    const post = (gym.feed || []).find((p) => p.id === postId);
    if (!post) return res.status(404).json({ error: 'Publicación no encontrada.' });

    if (!post.reactions) post.reactions = { gloves: [], fire: [], trophy: [] };
    const arr = post.reactions[reaction] || [];
    const idx = arr.indexOf(user.id);
    if (idx >= 0) {
      arr.splice(idx, 1);
    } else {
      arr.push(user.id);
    }
    post.reactions[reaction] = arr;
    saveOnlineDb(onlineDb);

    res.json({ ok: true, gym: buildGymSnapshot(code) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ============================================================================
// EXISTING VISION AI & LOCAL DEVICE STATE ENDPOINTS
// ============================================================================

app.post('/api/analyze-meal-photo', async (req, res) => {
  try {
    const { imageBase64, mimeType, provider = 'gemini', apiKey: bodyKey, userHint } = req.body || {};
    const apiKey = bodyKey || process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.json({ mode: 'needs_local_or_key', message: 'Sin API key externa configurada' });
    }

    const cleanBase64 = (imageBase64 || '').replace(/^data:image\/\w+;base64,/, '');
    const prompt = `Eres un nutricionista deportivo especializado en boxeo olímpico (75 kg). Analiza esta foto de comida${userHint ? ` (${userHint})` : ''}. Devuelve SOLO JSON con: {"dishName":"string","confidence":90,"digestionSpeed":"rapida|media|lenta","boxerVerdict":"string","items":[{"name":"string","grams":150,"kcal":250,"p":30,"c":20,"f":5}]}`;

    if (provider === 'openai') {
      const r = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          response_format: { type: 'json_object' },
          messages: [
            {
              role: 'user',
              content: [
                { type: 'text', text: prompt },
                { type: 'image_url', image_url: { url: `data:${mimeType || 'image/jpeg'};base64,${cleanBase64}` } },
              ],
            },
          ],
        }),
      });
      if (!r.ok) throw new Error(`OpenAI error ${r.status}`);
      const d = await r.json();
      return res.json({ mode: 'cloud_vision', analysis: JSON.parse(d.choices[0].message.content) });
    }

    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(apiKey)}`;
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }, { inline_data: { mime_type: mimeType || 'image/jpeg', data: cleanBase64 } }] }],
        generationConfig: { temperature: 0.2, responseMimeType: 'application/json' },
      }),
    });
    if (!r.ok) throw new Error(`Gemini error ${r.status}`);
    const d = await r.json();
    const raw = (d.candidates?.[0]?.content?.parts?.[0]?.text || '{}').replace(/```json|```/g, '').trim();
    return res.json({ mode: 'cloud_vision', analysis: JSON.parse(raw) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/state', (_req, res) => {
  try {
    if (fs.existsSync(STATE_FILE)) {
      res.type('json').send(fs.readFileSync(STATE_FILE, 'utf-8'));
    } else {
      res.json({ savedState: null });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/state', (req, res) => {
  try {
    const payload = JSON.stringify(
      {
        savedState: req.body.savedState,
        savedRoster: req.body.savedRoster || null,
        updatedAt: new Date().toISOString(),
      },
      null,
      2
    );
    const tempFile = `${STATE_FILE}.tmp`;
    fs.writeFileSync(tempFile, payload, 'utf-8');
    fs.renameSync(tempFile, STATE_FILE);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/state', (_req, res) => {
  try {
    if (fs.existsSync(STATE_FILE)) fs.unlinkSync(STATE_FILE);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const distPath = path.join(__dirname, 'dist');
const staticRoot = fs.existsSync(path.join(distPath, 'index.html')) ? distPath : __dirname;

app.use((req, res, next) => {
  if (/^\/(server\.js|package\.json|render\.yaml|data)/i.test(req.path)) {
    return res.status(404).end();
  }
  next();
});
app.use(express.static(staticRoot));
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api/')) {
    const idx = path.join(staticRoot, 'index.html');
    if (fs.existsSync(idx)) return res.sendFile(idx);
  }
  next();
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`RINGFUEL Pro Online Cloud Server running on http://0.0.0.0:${PORT}`);
});
