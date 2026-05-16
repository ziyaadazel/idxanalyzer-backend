// ============================================
// IDX ANALYZER — BACKEND API
// Stack: Node.js + Express + Supabase
// Deploy: Railway (railway.app)
// ============================================

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import Anthropic from '@anthropic-ai/sdk';
import crypto from 'crypto';
import multer from 'multer';
import pdfParse from 'pdf-parse';

const app = express();

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const config = {
  port: process.env.PORT || 3001,
  supabaseUrl: process.env.SUPABASE_URL,
  supabaseServiceKey: process.env.SUPABASE_SERVICE_KEY, // service role key (backend only!)
  supabaseAnonKey: process.env.SUPABASE_ANON_KEY,
  midtransServerKey: process.env.MIDTRANS_SERVER_KEY,
  midtransSandbox: process.env.NODE_ENV !== 'production',
  anthropicApiKey: process.env.ANTHROPIC_API_KEY,
  frontendUrl: process.env.FRONTEND_URL || 'http://localhost:3000',
};

// Supabase admin client (bypass RLS)
const supabase = createClient(config.supabaseUrl, config.supabaseServiceKey);

// Anthropic client
const anthropic = new Anthropic({ apiKey: config.anthropicApiKey });

// ─────────────────────────────────────────────
// MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: config.frontendUrl, credentials: true }));

// Rate limiting global
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100,
  message: { error: 'Terlalu banyak request, coba lagi dalam 15 menit.' }
}));

// Rate limiting ketat untuk endpoint analisis
const analysisLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 jam
  max: 10,
  message: { error: 'Terlalu banyak analisis, coba lagi dalam 1 jam.' }
});

// Multer untuk upload PDF (max 50MB)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Hanya file PDF yang didukung'));
  }
});

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE
// Verifikasi JWT dari Supabase
// ─────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token tidak ditemukan' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verifikasi token dengan Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Token tidak valid atau expired' });

    req.user = user;
    req.userId = user.id;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Gagal verifikasi token' });
  }
}

// ─────────────────────────────────────────────
// QUOTA MIDDLEWARE
// Cek apakah user boleh melakukan analisis
// ─────────────────────────────────────────────
async function checkQuota(req, res, next) {
  try {
    const { data, error } = await supabase
      .rpc('can_user_analyze', { p_user_id: req.userId });

    if (error) throw error;

    if (!data.allowed) {
      const messages = {
        free_quota_exhausted: 'Kuota gratis 5x sudah habis. Upgrade untuk lanjut analisis.',
        monthly_quota_exhausted: `Kuota bulanan tier Basic (20x) sudah habis. Upgrade ke Pro untuk unlimited.`,
      };
      return res.status(402).json({
        error: messages[data.reason] || 'Kuota habis',
        reason: data.reason,
        tier: data.tier,
        upgrade_url: `${config.frontendUrl}/#harga`
      });
    }

    req.quotaInfo = data;
    next();
  } catch (err) {
    console.error('Quota check error:', err);
    return res.status(500).json({ error: 'Gagal cek quota' });
  }
}

// ─────────────────────────────────────────────
// ROUTES: AUTH
// ─────────────────────────────────────────────

// Register
app.post('/auth/register', express.json(), async (req, res) => {
  const { email, password, full_name } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email dan password wajib diisi' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password minimal 8 karakter' });
  }

  const { data, error } = await supabase.auth.admin.createUser({
    email,
    password,
    user_metadata: { full_name: full_name || '' },
    email_confirm: true // skip email confirmation untuk MVP
  });

  if (error) return res.status(400).json({ error: error.message });

  return res.json({
    message: 'Registrasi berhasil. Kamu mendapat 5x analisis gratis!',
    user: { id: data.user.id, email: data.user.email }
  });
});

// Waitlist (email dari landing page, sebelum auth)
app.post('/waitlist', express.json(), async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email wajib diisi' });

  const { error } = await supabase
    .from('waitlist')
    .insert({ email, source: req.body.source || 'landing' });

  // Abaikan duplicate email error
  if (error && !error.message.includes('duplicate')) {
    return res.status(400).json({ error: error.message });
  }

  return res.json({ message: 'Berhasil! Kami akan hubungi kamu segera.' });
});

// ─────────────────────────────────────────────
// ROUTES: QUOTA & SUBSCRIPTION
// ─────────────────────────────────────────────

// GET: status quota dan subscription user
app.get('/me/quota', requireAuth, async (req, res) => {
  const { data: quota, error: qErr } = await supabase
    .from('quotas')
    .select('*')
    .eq('user_id', req.userId)
    .single();

  const { data: sub, error: sErr } = await supabase
    .from('subscriptions')
    .select('*')
    .eq('user_id', req.userId)
    .single();

  if (qErr || sErr) return res.status(500).json({ error: 'Gagal ambil data quota' });

  const tierLimits = { free: 5, basic: 20, pro: -1, pro_plus: -1 };
  const limit = tierLimits[sub.tier] ?? 5;

  return res.json({
    tier: sub.tier,
    subscription_status: sub.status,
    expires_at: sub.expires_at,
    free_used: quota.free_used,
    monthly_used: quota.monthly_used,
    total_used: quota.total_used,
    monthly_limit: limit,
    monthly_remaining: limit === -1 ? -1 : Math.max(0, limit - quota.monthly_used),
    is_unlimited: limit === -1,
  });
});

// GET: history analisis user
app.get('/me/analyses', requireAuth, async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  const { data, error, count } = await supabase
    .from('analyses')
    .select('id, ticker, company_name, year, industry, rating, score, created_at', { count: 'exact' })
    .eq('user_id', req.userId)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) return res.status(500).json({ error: error.message });
  return res.json({ analyses: data, total: count, page, limit });
});

// GET: detail satu analisis
app.get('/me/analyses/:id', requireAuth, async (req, res) => {
  const { data, error } = await supabase
    .from('analyses')
    .select('*')
    .eq('id', req.params.id)
    .eq('user_id', req.userId) // pastikan milik user ini
    .single();

  if (error || !data) return res.status(404).json({ error: 'Analisis tidak ditemukan' });
  return res.json(data);
});

// ─────────────────────────────────────────────
// ROUTES: ANALISIS
// ─────────────────────────────────────────────
app.post(
  '/analyze',
  requireAuth,
  analysisLimiter,
  checkQuota,
  upload.single('pdf'),
  async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'File PDF wajib diupload' });

    try {
      // 1. Extract teks dari PDF
      let pdfText = '';
      try {
        const parsed = await pdfParse(req.file.buffer);
        pdfText = parsed.text;
      } catch (pdfErr) {
        return res.status(400).json({ error: 'Gagal membaca PDF. Pastikan file tidak terproteksi.' });
      }

      if (pdfText.length < 500) {
        return res.status(400).json({ error: 'PDF tidak bisa dibaca atau teks terlalu sedikit.' });
      }

      // 2. Panggil Claude API
      const prompt = buildAnalysisPrompt(pdfText.substring(0, 20000), req.file.originalname);

      const message = await anthropic.messages.create({
        model: 'claude-haiku-4-5-20251001', // Haiku lebih murah, cukup untuk tugas ini
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }]
      });

      const rawText = message.content[0].text;
      const jsonMatch = rawText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('Format output AI tidak valid');

      const result = JSON.parse(jsonMatch[0]);
      const tokensUsed = message.usage.input_tokens + message.usage.output_tokens;

      // 3. Simpan hasil ke database
      const { data: savedAnalysis, error: saveErr } = await supabase
        .from('analyses')
        .insert({
          user_id: req.userId,
          ticker: result.ticker || null,
          company_name: result.company_name || null,
          year: result.year || null,
          industry: result.industry || null,
          filename: req.file.originalname,
          result: result,
          rating: result.recommendation?.rating || null,
          score: result.recommendation?.score || null,
          tokens_used: tokensUsed,
        })
        .select('id')
        .single();

      if (saveErr) console.error('Save analysis error:', saveErr);

      // 4. Increment quota
      await supabase.rpc('increment_quota', { p_user_id: req.userId });

      // 5. Return hasil
      return res.json({
        analysis_id: savedAnalysis?.id,
        result,
        tokens_used: tokensUsed,
        quota_info: req.quotaInfo,
      });

    } catch (err) {
      console.error('Analysis error:', err);
      return res.status(500).json({ error: 'Gagal menganalisis: ' + err.message });
    }
  }
);

// ─────────────────────────────────────────────
// ROUTES: PAYMENT (MIDTRANS)
// ─────────────────────────────────────────────
const TIERS = {
  basic:    { price: 99000,  name: 'IDX Analyzer Basic',  duration_days: 30 },
  pro:      { price: 299000, name: 'IDX Analyzer Pro',    duration_days: 30 },
  pro_plus: { price: 499000, name: 'IDX Analyzer Pro+',   duration_days: 30 },
};

// Create payment (generate Snap token Midtrans)
app.post('/payment/create', requireAuth, express.json(), async (req, res) => {
  const { tier } = req.body;

  if (!TIERS[tier]) {
    return res.status(400).json({ error: 'Tier tidak valid. Pilih: basic, pro, pro_plus' });
  }

  const tierInfo = TIERS[tier];
  const orderId = `IDX-${req.userId.slice(0, 8).toUpperCase()}-${Date.now()}`;

  // Ambil data profile user
  const { data: profile } = await supabase
    .from('profiles')
    .select('email, full_name')
    .eq('id', req.userId)
    .single();

  // Request ke Midtrans Snap API
  const midtransUrl = config.midtransSandbox
    ? 'https://app.sandbox.midtrans.com/snap/v1/transactions'
    : 'https://app.midtrans.com/snap/v1/transactions';

  const authKey = Buffer.from(config.midtransServerKey + ':').toString('base64');

  try {
    const mtRes = await fetch(midtransUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${authKey}`,
      },
      body: JSON.stringify({
        transaction_details: {
          order_id: orderId,
          gross_amount: tierInfo.price,
        },
        customer_details: {
          email: profile?.email || req.user.email,
          first_name: profile?.full_name || 'User',
        },
        item_details: [{
          id: tier,
          price: tierInfo.price,
          quantity: 1,
          name: tierInfo.name,
        }],
        callbacks: {
          finish: `${config.frontendUrl}/payment/success`,
          error: `${config.frontendUrl}/payment/error`,
          pending: `${config.frontendUrl}/payment/pending`,
        },
        custom_field1: req.userId,   // untuk tracking di webhook
        custom_field2: tier,
      })
    });

    const mtData = await mtRes.json();
    if (!mtRes.ok) throw new Error(mtData.error_messages?.join(', ') || 'Midtrans error');

    // Log payment ke database
    await supabase.from('payment_logs').insert({
      user_id: req.userId,
      midtrans_order_id: orderId,
      amount_idr: tierInfo.price,
      tier,
      status: 'pending',
    });

    return res.json({
      snap_token: mtData.token,
      snap_redirect_url: mtData.redirect_url,
      order_id: orderId,
    });

  } catch (err) {
    console.error('Payment create error:', err);
    return res.status(500).json({ error: 'Gagal membuat payment: ' + err.message });
  }
});

// Midtrans Webhook (notifikasi pembayaran)
app.post('/payment/webhook', express.json(), async (req, res) => {
  const { order_id, transaction_status, fraud_status, custom_field1, custom_field2, gross_amount } = req.body;

  // Verifikasi signature dari Midtrans
  const signatureKey = crypto
    .createHash('sha512')
    .update(order_id + req.body.status_code + gross_amount + config.midtransServerKey)
    .digest('hex');

  if (signatureKey !== req.body.signature_key) {
    console.error('Invalid Midtrans signature');
    return res.status(403).json({ error: 'Invalid signature' });
  }

  const userId = custom_field1;
  const tier = custom_field2;
  const isSuccess =
    (transaction_status === 'settlement' || transaction_status === 'capture') &&
    (fraud_status === 'accept' || !fraud_status);

  // Update payment log
  await supabase
    .from('payment_logs')
    .update({ status: isSuccess ? 'success' : transaction_status, raw_payload: req.body })
    .eq('midtrans_order_id', order_id);

  if (isSuccess && userId && tier && TIERS[tier]) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + TIERS[tier].duration_days);

    // Update subscription user
    await supabase
      .from('subscriptions')
      .update({
        tier,
        status: 'active',
        price_idr: TIERS[tier].price,
        started_at: new Date().toISOString(),
        expires_at: expiresAt.toISOString(),
        midtrans_order_id: order_id,
        updated_at: new Date().toISOString(),
      })
      .eq('user_id', userId);

    // Reset monthly quota saat upgrade
    await supabase
      .from('quotas')
      .update({ monthly_used: 0 })
      .eq('user_id', userId);

    console.log(`✅ Payment success: user ${userId} → tier ${tier}`);
  }

  return res.json({ status: 'ok' });
});

// ─────────────────────────────────────────────
// HEALTHCHECK
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// PUBLIC: Analyze text (no auth, for frontend demo)
// ─────────────────────────────────────────────
app.post('/analyze-text', express.json({ limit: '2mb' }), async (req, res) => {
  const { text, filename } = req.body;
  if (!text || text.length < 100) {
    return res.status(400).json({ error: 'Teks terlalu pendek atau kosong' });
  }
  try {
    const prompt = buildAnalysisPrompt(text.substring(0, 20000), filename || 'annual-report.pdf');
    const message = await anthropic.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }]
    });
    const raw = message.content[0].text;
    const match = raw.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('Format tidak valid');
    const result = JSON.parse(match[0]);
    return res.json({ result });
  } catch (err) {
    console.error('analyze-text error:', err);
    return res.status(500).json({ error: 'Gagal menganalisis: ' + err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', env: process.env.NODE_ENV, timestamp: new Date().toISOString() });
});

// ─────────────────────────────────────────────
// HELPER: PROMPT BUILDER
// ─────────────────────────────────────────────
function buildAnalysisPrompt(text, filename) {
  return `Kamu adalah analis keuangan senior IDX. Analisis laporan tahunan berikut.
File: ${filename}
Konten: ${text}

Kembalikan HANYA JSON valid tanpa markdown:
{
  "company_name":"nama perusahaan lengkap",
  "ticker":"kode saham atau null",
  "year":"tahun laporan",
  "industry":"sektor",
  "summary":"ringkasan 2-3 kalimat",
  "revenue":"Rp X,X T",
  "net_income":"laba bersih",
  "total_assets":"total aset",
  "ratios":{
    "current_ratio":{"value":"X,Xx","label":"Current Ratio","status":"baik"},
    "roe":{"value":"X%","label":"ROE","status":"baik"},
    "roa":{"value":"X%","label":"ROA","status":"cukup"},
    "npm":{"value":"X%","label":"Net Profit Margin","status":"baik"},
    "der":{"value":"X,Xx","label":"DER","status":"baik"},
    "eps":{"value":"Rp XXX","label":"EPS","status":"baik"},
    "revenue_growth":{"value":"X%","label":"Revenue Growth","status":"cukup"},
    "ebitda_margin":{"value":"X%","label":"EBITDA Margin","status":"baik"}
  },
  "strengths":["kekuatan 1 dengan angka","kekuatan 2","kekuatan 3"],
  "weaknesses":["kelemahan 1 dengan angka","kelemahan 2"],
  "opportunities":["peluang 1","peluang 2"],
  "risks":["risiko 1","risiko 2"],
  "recommendation":{
    "rating":"BELI",
    "score":72,
    "reasoning":"alasan 2-3 kalimat berbasis data",
    "target_price":"Rp X.XXX",
    "stop_loss":"Rp X.XXX",
    "investor_type":"tipe investor yang cocok"
  }
}`;
}

// ─────────────────────────────────────────────
// ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Upload error: ' + err.message });
  }
  console.error('Unhandled error:', err);
  return res.status(500).json({ error: 'Internal server error' });
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
app.listen(config.port, () => {
  console.log(`🚀 IDX Analyzer API running on port ${config.port}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   Midtrans: ${config.midtransSandbox ? 'SANDBOX' : 'PRODUCTION'}`);
});
