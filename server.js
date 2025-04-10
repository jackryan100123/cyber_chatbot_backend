const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const compression = require('compression');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Trust proxy in production
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// Security Middleware
app.use(helmet());
app.use(compression());

// Rate limiting with proxy support
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip;
  }
});
app.use('/api/', limiter);

app.use(express.json({ limit: '10kb' }));
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

// CORS configuration
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://cyber-chatbot-backend.onrender.com', 'http://localhost:5173', 'http://localhost:5174']
    : ['http://localhost:5173', 'http://localhost:5174'],
  methods: ['GET'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400
};
app.use(cors(corsOptions));

// GNews API configuration
const GNEWS_API_KEY = process.env.GNEWS_API_KEY;
const GNEWS_BASE_URL = 'https://gnews.io/api/v4';

// Cache directory and file paths
const CACHE_DIR = process.env.NODE_ENV === 'production' 
  ? '/tmp/cache' 
  : path.join(__dirname, 'cache');
const CACHE_FILE = path.join(CACHE_DIR, 'news_cache.json');

// Ensure cache directory exists with proper permissions
if (!fs.existsSync(CACHE_DIR)) {
  try {
    fs.mkdirSync(CACHE_DIR, { mode: 0o755, recursive: true });
    console.log(`Cache directory created at: ${CACHE_DIR}`);
  } catch (error) {
    console.error('Error creating cache directory:', error);
  }
}

// Function to read cache file
const readCache = () => {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf8');
      return JSON.parse(data);
    }
  } catch (error) {
    console.error('Error reading cache:', error);
  }
  return null;
};

// Function to write cache file
const writeCache = (data) => {
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2), { mode: 0o644 });
    return true;
  } catch (error) {
    console.error('Error writing cache:', error);
    return false;
  }
};

// Function to check if cache is valid
const isCacheValid = (cache) => {
  if (!cache || !cache.timestamp) return false;
  const now = Date.now();
  const hours24 = 24 * 60 * 60 * 1000;
  return now - cache.timestamp < hours24;
};

// Function to fetch news from GNews
const fetchNews = async () => {
  try {
    console.log('Fetching news from GNews API...');
    console.log('Using API Key:', GNEWS_API_KEY ? 'Present' : 'Missing');
    
    const response = await axios.get(`${GNEWS_BASE_URL}/search`, {
      params: {
        q: '(cybercrime OR cybersecurity OR "cyber attack" OR "data breach" OR "online fraud") AND (india OR indian)',
        lang: 'en',
        country: 'in',
        max: 10,
        apikey: GNEWS_API_KEY
      }
    });

    console.log('GNews API Response Status:', response.status);
    console.log('Number of articles:', response.data?.articles?.length || 0);

    if (response.data && response.data.articles && response.data.articles.length > 0) {
      const articles = response.data.articles.map(article => ({
        title: article.title,
        description: article.description,
        url: article.url,
        publishedAt: article.publishedAt,
        source: {
          name: article.source.name
        }
      }));

      const cacheData = {
        articles,
        timestamp: Date.now()
      };
      
      if (writeCache(cacheData)) {
        console.log('Successfully cached news articles');
      } else {
        console.error('Failed to cache news articles');
      }
      
      return articles;
    }
    throw new Error('No articles found in response');
  } catch (error) {
    console.error('Error fetching news:', error.message);
    if (error.response) {
      console.error('Error response data:', error.response.data);
      console.error('Error response status:', error.response.status);
    }
    throw error;
  }
};

// Route to get news
app.get('/api/news', async (req, res) => {
  try {
    console.log('Received news request');
    console.log('Request headers:', req.headers);
    console.log('Origin:', req.headers.origin);
    console.log('IP:', req.ip);
    
    const cache = readCache();
    console.log('Cache status:', cache ? 'Exists' : 'Does not exist');
    
    if (isCacheValid(cache)) {
      console.log('Returning cached news');
      return res.json(cache.articles);
    }

    console.log('Cache invalid or empty, fetching new news');
    const articles = await fetchNews();
    
    if (articles.length === 0) {
      console.log('No articles found');
      return res.status(404).json({ 
        status: 'error',
        message: 'No news articles found'
      });
    }

    console.log('Returning new news articles');
    res.json(articles);
  } catch (error) {
    console.error('Error in news route:', error);
    res.status(500).json({ 
      status: 'error',
      message: 'Failed to fetch news',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  const cache = readCache();
  res.json({ 
    status: 'ok',
    environment: process.env.NODE_ENV || 'development',
    cache: {
      exists: !!cache,
      isValid: isCacheValid(cache),
      timestamp: cache?.timestamp,
      articleCount: cache?.articles?.length || 0,
      directory: CACHE_DIR
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    status: 'error',
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'error',
    message: 'Route not found'
  });
});

// Start server
const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Cache directory: ${CACHE_DIR}`);
  console.log(`CORS enabled for: ${corsOptions.origin.join(', ')}`);
  console.log(`Trust proxy: ${process.env.NODE_ENV === 'production' ? 'enabled' : 'disabled'}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('UNHANDLED REJECTION! 💥 Shutting down...');
  console.error(err);
  server.close(() => {
    process.exit(1);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.error(err);
  process.exit(1);
}); 