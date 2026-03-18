const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Security patterns to scan for
const securityPatterns = [
  {
    pattern: /eval\s*\(/gi,
    severity: 'high',
    description: 'Dangerous use of eval() function detected - can lead to code injection'
  },
  {
    pattern: /sk-[a-zA-Z0-9]{40,}/g,
    severity: 'critical',
    description: 'Hardcoded OpenAI API key detected'
  },
  {
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'Hardcoded GitHub personal access token detected'
  },
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    description: 'Hardcoded AWS access key detected'
  },
  {
    pattern: /child_process/gi,
    severity: 'medium',
    description: 'Use of child_process module - potential command injection risk'
  },
  {
    pattern: /require\s*\(\s*['"]child_process['"]/gi,
    severity: 'medium',
    description: 'Import of child_process module detected'
  },
  {
    pattern: /exec\s*\(/gi,
    severity: 'high',
    description: 'Use of exec() function - potential command injection'
  },
  {
    pattern: /spawn\s*\(/gi,
    severity: 'medium',
    description: 'Use of spawn() function - review for security risks'
  }
];

// Helper function to find line number of a match
function getLineNumber(code, index) {
  const beforeMatch = code.substring(0, index);
  return beforeMatch.split('\n').length;
}

// Scan code for security issues
function scanCode(code) {
  const findings = [];
  
  securityPatterns.forEach(({ pattern, severity, description }) => {
    let match;
    while ((match = pattern.exec(code)) !== null) {
      const line = getLineNumber(code, match.index);
      findings.push({
        severity,
        description,
        line
      });
    }
  });
  
  return findings;
}

// Routes
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Apex Security Scanner'
  });
});

app.post('/', (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code || typeof code !== 'string') {
      return res.status(400).json({
        error: 'Invalid request',
        message: 'Code field is required and must be a string'
      });
    }
    
    const findings = scanCode(code);
    
    res.json({
      findings
    });
  } catch (error) {
    res.status(500).json({
      error: 'Internal server error',
      message: 'Failed to scan code'
    });
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not found',
    message: 'Endpoint not found'
  });
});

// Error handler
app.use((error, req, res, next) => {
  console.error('Error:', error);
  res.status(500).json({
    error: 'Internal server error',
    message: 'Something went wrong'
  });
});

app.listen(PORT, () => {
  console.log(`Apex Security Scanner API running on port ${PORT}`);
});