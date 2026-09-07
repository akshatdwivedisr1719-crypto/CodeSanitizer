import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';
import { spawn } from 'child_process';
import { defineConfig, Plugin } from 'vite';

function pythonApiPlugin(): Plugin {
  return {
    name: 'python-api-plugin',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ? new URL(req.url, 'http://localhost:3000') : null;

        if (url && url.pathname === '/api/scan' && req.method === 'POST') {
          let body = '';
          req.on('data', chunk => { body += chunk; });
          req.on('end', () => {
            try {
              const { code } = JSON.parse(body || '{}');
              if (typeof code !== 'string') {
                res.statusCode = 400;
                res.setHeader('Content-Type', 'application/json');
                return res.end(JSON.stringify({ error: 'Code string required' }));
              }

              const py = spawn('python3', ['analyzer.py', '--stdin', '--json'], {
                cwd: process.cwd(),
              });

              let stdout = '';
              let stderr = '';

              py.stdout.on('data', d => { stdout += d; });
              py.stderr.on('data', d => { stderr += d; });

              py.on('close', code => {
                res.setHeader('Content-Type', 'application/json');
                if (code === 0 && stdout) {
                  res.statusCode = 200;
                  res.end(stdout);
                } else {
                  res.statusCode = 200;
                  try {
                    res.end(stdout || JSON.stringify({ success: false, message: stderr || 'Analyzer failed' }));
                  } catch {
                    res.end(JSON.stringify({ success: false, message: stderr || 'Execution error' }));
                  }
                }
              });

              py.stdin.write(code);
              py.stdin.end();
            } catch (err: any) {
              res.statusCode = 500;
              res.setHeader('Content-Type', 'application/json');
              res.end(JSON.stringify({ error: err.message }));
            }
          });
          return;
        }

        if (url && url.pathname === '/api/file' && req.method === 'GET') {
          const filePath = url.searchParams.get('path');
          const safePaths = [
            'test_code/vulnerable.py',
            'test_code/safe.py',
            'app.py',
            'analyzer.py',
            'package_checker.py',
            'rules.py',
            'report.py',
            'requirements.txt',
            'README.md'
          ];
          if (filePath && safePaths.includes(filePath)) {
            const fullPath = path.join(process.cwd(), filePath);
            if (fs.existsSync(fullPath)) {
              res.setHeader('Content-Type', 'text/plain; charset=utf-8');
              return res.end(fs.readFileSync(fullPath, 'utf-8'));
            }
          }
          res.statusCode = 404;
          return res.end('File not found');
        }

        next();
      });
    }
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), pythonApiPlugin()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      hmr: process.env.DISABLE_HMR !== 'true',
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
