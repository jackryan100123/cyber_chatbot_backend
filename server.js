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

// Security Middleware
app.use(helmet()); // Set security HTTP headers
app.use(compression()); // Compress all routes

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later'
});
app.use('/api/', limiter);

// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' })); // Body limit is 10kb

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());

// Data sanitization against XSS
app.use(xss());

// Prevent parameter pollution
app.use(hpp());

// CORS configuration
const corsOptions = {
  origin: ['http://localhost:5173', 'http://localhost:5174'],
  methods: ['GET'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 86400 // 24 hours
};
app.use(cors(corsOptions));

// GNews API configuration
const GNEWS_API_KEY = process.env.GNEWS_API_KEY;
const GNEWS_BASE_URL = 'https://gnews.io/api/v4';

// Cache directory and file paths
const CACHE_DIR = path.join(__dirname, 'cache');
const CACHE_FILE = path.join(CACHE_DIR, 'news_cache.json');

// Ensure cache directory exists with proper permissions
if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { mode: 0o755 });
}

// Function to read cache file with error handling
const readCache = () => {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf8');
      return JSON.parse(data);
    }
  } catch (error) {
    console.error('Error reading cache:', error);
    return null;
  }
  return null;
};

// Function to write cache file with error handling
const writeCache = (data) => {
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2), { mode: 0o644 });
    return true;
  } catch (error) {
    console.error('Error writing cache:', error);
    return false;
  }
};

// Function to check if cache is valid (less than 24 hours old)
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
    
    const response = await axios.get(`${GNEWS_BASE_URL}/search`, {
      params: {
        q: '(cybercrime OR cybersecurity OR "cyber attack" OR "data breach" OR "online fraud") AND (india OR indian)',
        lang: 'en',
        country: 'in',
        max: 10,
        apikey: GNEWS_API_KEY
      }
    });

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
      writeCache(cacheData);
      return articles;
    }
    throw new Error('No articles found');
  } catch (error) {
    console.error('Error fetching news:', error.message);
    throw error;
  }
};

// Route to get news with enhanced security
app.get('/api/news', async (req, res) => {
  try {
    // Read from cache
    const cache = readCache();
    
    // Check if we have valid cached news
    if (isCacheValid(cache)) {
      return res.json(cache.articles);
    }

    // Fetch new news
    const articles = await fetchNews();
    
    if (articles.length === 0) {
      return res.status(404).json({ 
        status: 'error',
        message: 'No news articles found'
      });
    }

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

// Health check endpoint with security headers
app.get('/health', (req, res) => {
  const cache = readCache();
  res.json({ 
    status: 'ok',
    cache: {
      exists: !!cache,
      isValid: isCacheValid(cache),
      timestamp: cache?.timestamp,
      articleCount: cache?.articles?.length || 0
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

// Start server with error handling
const server = app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Cache directory: ${CACHE_DIR}`);
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