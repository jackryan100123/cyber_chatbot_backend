const express = require('express');
const cors = require('cors');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
require('dotenv').config();

// Validate required environment variables
const validateEnv = () => {
    const requiredEnvVars = [
        'NODE_ENV'
    ];

    const optionalEnvVars = [
        'CHECKPHISH_API_KEY'
    ];

    const missingRequiredEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
    const missingOptionalEnvVars = optionalEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missingRequiredEnvVars.length > 0) {
        throw new Error(`Missing required environment variables: ${missingRequiredEnvVars.join(', ')}`);
    }

    if (missingOptionalEnvVars.length > 0) {
        console.warn(`Warning: Missing optional environment variables: ${missingOptionalEnvVars.join(', ')}`);
        console.warn('Some features may be limited or unavailable.');
    }
    
    return true;
};

const app = express();
const port = process.env.PORT || 5000;

// CORS configuration for production
const corsOptions = {
    origin: process.env.NODE_ENV === 'production'
        ? ['https://cyber-saathi.onrender.com', 'https://cyber-chatbot-frontend.onrender.com']
        : ['http://localhost:5173', 'http://localhost:5174'],
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 200
};

// Apply CORS before other middleware
app.use(cors(corsOptions));

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:", "http:"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", 
                "https://api.groq.com", 
                "https://developers.checkphish.ai",
                "https://cyber-saathi.onrender.com",
                "https://cyber-chatbot-frontend.onrender.com"
            ]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// Enable compression
app.use(compression());

// Rate limiting configuration
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { 
        status: 'error', 
        message: 'Too many requests from this IP, please try again later' 
    },
    standardHeaders: true,
    legacyHeaders: false
});

// Apply rate limiting to all routes
app.use(limiter);

app.use(express.json({ limit: '10kb' })); // Limit body size

// CheckPhish API Configuration
const CHECKPHISH_API_KEY = process.env.CHECKPHISH_API_KEY;
const CHECKPHISH_SCAN_URL = 'https://developers.checkphish.ai/api/neo/scan';
const CHECKPHISH_STATUS_URL = 'https://developers.checkphish.ai/api/neo/scan/status';

// Function to poll for scan results
const pollForResults = async (jobID, apiKey, maxAttempts = 10) => {
    console.log(`Starting polling for jobID: ${jobID}`);
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
            console.log(`Polling attempt ${attempt + 1} of ${maxAttempts}`);
            
            const resultResponse = await axios.post(CHECKPHISH_STATUS_URL, {
                apiKey: apiKey,
                jobID: jobID,
                insights: true
            });

            console.log(`Poll response status: ${resultResponse.data.status}`);
            console.log('Poll response data:', JSON.stringify(resultResponse.data, null, 2));

            if (resultResponse.data.status === 'DONE') {
                console.log('Scan completed successfully');
                return resultResponse.data;
            }

            // Wait for 3 seconds before next attempt (increased from 2)
            console.log('Waiting 3 seconds before next attempt...');
            await new Promise(resolve => setTimeout(resolve, 3000));
        } catch (error) {
            console.error(`Polling attempt ${attempt + 1} failed:`, error.response?.data || error.message);
            if (attempt === maxAttempts - 1) throw error;
        }
    }
    throw new Error('Scan timed out after maximum polling attempts');
};

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV
    });
});

// URL validation middleware
const validateUrl = (req, res, next) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({
            success: false,
            message: 'URL is required'
        });
    }
    try {
        new URL(url); // Validate URL format
        next();
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: 'Invalid URL format'
        });
    }
};

// Endpoint to scan URLs
app.post('/api/scan-url', validateUrl, async (req, res) => {
    if (!process.env.CHECKPHISH_API_KEY) {
        return res.status(503).json({
            success: false,
            message: 'URL scanning service is currently unavailable. CHECKPHISH_API_KEY is not configured.'
        });
    }

    const { url } = req.body;

    try {
        // Step 1: Submit URL for scanning
        const scanResponse = await axios.post(CHECKPHISH_SCAN_URL, {
            apiKey: process.env.CHECKPHISH_API_KEY,
            urlInfo: { url },
            scanType: 'quick'
        });

        if (!scanResponse.data?.jobID) {
            throw new Error('Invalid scan response');
        }

        // Step 2: Poll for results
        const scanResult = await pollForResults(scanResponse.data.jobID, process.env.CHECKPHISH_API_KEY);
        
        // Format the response
        const formattedResponse = {
            success: true,
            result: {
                url: scanResult.url,
                status: scanResult.status,
                disposition: scanResult.disposition,
                categories: scanResult.categories,
                scan_time: {
                    start: scanResult.scan_start_ts,
                    end: scanResult.scan_end_ts
                },
                insights_url: scanResult.insights,
                screenshot: scanResult.screenshot_path,
                brand: scanResult.brand
            }
        };

        return res.json(formattedResponse);

    } catch (error) {
        console.error('Error in URL scan:', error);
        const statusCode = error.response?.status || 500;
        return res.status(statusCode).json({
            success: false,
            message: error.response?.data?.message || error.message || 'Error scanning URL',
            error: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

// Add this after your CORS configuration
app.post('/api/test', (req, res) => {
    console.log('Test endpoint hit');
    console.log('Request body:', req.body);
    res.json({
        success: true,
        message: 'Test endpoint working',
        receivedData: req.body
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        status: 'error',
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.stack : undefined
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
const startServer = async () => {
    try {
        validateEnv();
        app.listen(port, '0.0.0.0', () => {
            console.log(`Server is running on port ${port}`);
        });
    } catch (error) {
        console.error('Server startup error:', error);
        process.exit(1);
    }
};

startServer();

// Graceful shutdown
const shutdown = () => {
    console.log('Shutting down gracefully...');
    process.exit(0);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);