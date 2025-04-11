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
        'VIRUSTOTAL_API_KEY'
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
const port = process.env.PORT || 10000;

// CORS configuration
const allowedOrigins = [
    'https://cyber-saathi.onrender.com', 
    'https://cyber-chatbot-frontend.onrender.com',
    'http://localhost:3000',
    'http://localhost:3001',
    'http://localhost:5173', 
    'http://localhost:5174'
];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, postman)
        if (!origin) {
            return callback(null, true);
        }
        
        if (allowedOrigins.indexOf(origin) !== -1 || origin.startsWith('http://localhost')) {
            callback(null, true);
        } else {
            console.warn(`Origin ${origin} not allowed by CORS`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400,
    optionsSuccessStatus: 200
};

// Apply CORS before other middleware
app.use(cors(corsOptions));

// Additional CORS headers for preflight requests
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.indexOf(origin) !== -1 || (origin && origin.startsWith('http://localhost'))) {
        res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', 'true');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }
    
    next();
});

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
                "https://cyber-chatbot-frontend.onrender.com",
                "https://cyber-chatbot-backend.onrender.com",
                "http://localhost:3000",
                "http://localhost:3001",
                "http://localhost:5173",
                "http://localhost:5174"
            ]
        }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginOpenerPolicy: { policy: "unsafe-none" }
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

// VirusTotal API Configuration
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/api/v3/urls';
const VIRUSTOTAL_RESULT_URL = 'https://www.virustotal.com/api/v3/analyses';

// Function to submit URL to VirusTotal
const submitUrlToVirusTotal = async (url, apiKey) => {
    const formData = new URLSearchParams();
    formData.append('url', url);

    const response = await axios.post(VIRUSTOTAL_SCAN_URL, formData, {
        headers: {
            'x-apikey': apiKey,
            'content-type': 'application/x-www-form-urlencoded'
        }
    });
    
    // Extract the analysis ID from the response
    const analysisId = response.data.data.id;
    
    // If there's a link to existing analysis, get the ID from there
    const analysisLink = response.data.data.links?.self;
    const existingAnalysisId = analysisLink ? analysisLink.split('/').pop() : null;
    
    return {
        data: {
            id: existingAnalysisId || analysisId
        }
    };
};

// Function to get VirusTotal scan results
const getVirusTotalResults = async (analysisId, apiKey) => {
    const response = await axios.get(`${VIRUSTOTAL_RESULT_URL}/${analysisId}`, {
        headers: {
            'x-apikey': apiKey
        }
    });
    return response.data;
};

// Function to poll VirusTotal results
const pollVirusTotalResults = async (analysisId, apiKey, maxAttempts = 20) => {
    console.log(`Starting VirusTotal polling for analysis ID: ${analysisId}`);
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
            console.log(`VirusTotal polling attempt ${attempt + 1} of ${maxAttempts}`);
            
            const result = await getVirusTotalResults(analysisId, apiKey);
            
            if (result.data.attributes.status === 'completed') {
                console.log('VirusTotal scan completed successfully');
                return result;
            }

            // Increase wait time between attempts (5 seconds)
            console.log('Waiting 5 seconds before next attempt...');
            await new Promise(resolve => setTimeout(resolve, 5000));
        } catch (error) {
            console.error(`VirusTotal polling attempt ${attempt + 1} failed:`, error.response?.data || error.message);
            
            // If we get a 404, the analysis might not be ready yet
            if (error.response?.status === 404) {
                console.log('Analysis not ready yet, waiting...');
                await new Promise(resolve => setTimeout(resolve, 5000));
                continue;
            }
            
            if (attempt === maxAttempts - 1) throw error;
            
            // Wait before retrying on error
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
    throw new Error('VirusTotal scan timed out after maximum polling attempts');
};

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

// Endpoint to scan URLs with VirusTotal
app.post('/api/scan-url-virustotal', validateUrl, async (req, res) => {
    if (!process.env.VIRUSTOTAL_API_KEY) {
        return res.status(503).json({
            success: false,
            message: 'URL scanning service is currently unavailable. VIRUSTOTAL_API_KEY is not configured.'
        });
    }

    const { url } = req.body;

    try {
        // Step 1: Submit URL for scanning
        const scanResponse = await submitUrlToVirusTotal(url, process.env.VIRUSTOTAL_API_KEY);
        
        if (!scanResponse.data?.id) {
            throw new Error('Invalid scan response from VirusTotal');
        }

        // Step 2: Poll for results
        const scanResult = await pollVirusTotalResults(scanResponse.data.id, process.env.VIRUSTOTAL_API_KEY);
        
        // Format the response
        const formattedResponse = {
            success: true,
            result: {
                id: scanResult.data.id,
                status: scanResult.data.attributes.status,
                stats: scanResult.data.attributes.stats,
                results: scanResult.data.attributes.results,
                scan_time: {
                    date: scanResult.data.attributes.date,
                    analysis_time: scanResult.data.attributes.analysis_time
                }
            }
        };

        return res.json(formattedResponse);

    } catch (error) {
        console.error('Error in VirusTotal URL scan:', error);
        const statusCode = error.response?.status || 500;
        return res.status(statusCode).json({
            success: false,
            message: error.response?.data?.message || error.message || 'Error scanning URL with VirusTotal',
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