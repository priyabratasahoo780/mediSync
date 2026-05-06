import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import path from 'path';
import morgan from 'morgan';
import helmet from 'helmet';
import compression from 'compression';
import { fileURLToPath } from 'url';
import { notFound, errorHandler } from './middleware/errorMiddleware.js';
import {
  securityAuditLogger,
  globalLimiter,
  authLimiter,
  passwordResetLimiter,
  adminLimiter,
  mongoSanitizer,
  xssSanitizer,
  hppProtection,
  secureHeaders,
  requestSizeGuard,
} from './middleware/securityMiddleware.js';

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'", "https://accounts.google.com"],
      connectSrc: ["'self'", "https://medi-sync-rho.vercel.app", "http://localhost:5173", "http://localhost:5174", "https://accounts.google.com"],
      frameSrc: ["'self'", "https://accounts.google.com"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,       
    includeSubDomains: true,
    preload: true,
  },
}));


app.use(compression());


const allowedOrigins = [
  'https://medi-sync-rho.vercel.app',
  'http://localhost:5173',
  'http://localhost:5174'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const isVercel = origin.endsWith('.vercel.app');
    const isLocal = origin.startsWith('http://localhost');
    if (allowedOrigins.indexOf(origin) !== -1 || isVercel || isLocal) {
      callback(null, true);
    } else {
      console.warn(`🚫 [CORS BLOCKED] Origin: ${origin}`);
      callback(new Error('CORS Policy: Origin not authorized by MediSync Security'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Cache-Control', 'Pragma', 'Expires'],
}));


app.use(requestSizeGuard);
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));


app.use(secureHeaders);


app.use('/api/', globalLimiter);


app.use('/api/admin/', adminLimiter);


app.use(mongoSanitizer);


app.use(xssSanitizer);


app.use(hppProtection);


app.use(securityAuditLogger);


if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
  app.use(morgan('dev'));
}


app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'active',
    message: 'MediSync Clinical Backend is Synchronized',
    security: 'Z+ Hardened',
    timestamp: new Date().toISOString(),
  });
});


import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import recordRoutes from './routes/recordRoutes.js';
import pharmacyRoutes from './routes/pharmacyRoutes.js';
import medicineRoutes from './routes/medicineRoutes.js';
import prescriptionRoutes from './routes/prescriptionRoutes.js';
import appointmentRoutes from './routes/appointmentRoutes.js';


app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', passwordResetLimiter);
app.use('/api/auth/reset-password', passwordResetLimiter);

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/records', recordRoutes);
app.use('/api/pharmacies', pharmacyRoutes);
app.use('/api/medicines', medicineRoutes);
app.use('/api/prescriptions', prescriptionRoutes);
app.use('/api/appointments', appointmentRoutes);


if (process.env.NODE_ENV === 'production') {
  const distPath = path.resolve(__dirname, '../dist');
  app.use(express.static(distPath));
  
  app.get(/.*/, (req, res) => {
    res.sendFile(path.resolve(distPath, 'index.html'));
  });
} else {
  app.get('/', (req, res) => {
    res.send('MediSync API is running in development mode — Z+ Security Active');
  });
}


app.use(notFound);
app.use(errorHandler);

export default app;
