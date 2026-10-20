import {defineConfig,devices} from '@playwright/test';

export default defineConfig({
  testDir:'./e2e',
  timeout:30_000,
  use:{baseURL:'http://127.0.0.1:5173',trace:'retain-on-failure'},
  projects:[
    {name:'chromium',use:{...devices['Desktop Chrome']}},
    {name:'mobile-chromium',use:{...devices['Pixel 7']}}
  ],
  webServer:[
    {
      command:'python backend/run.py',
      cwd:'..',
      port:5000,
      reuseExistingServer:false,
      env:{DATABASE_PATH:'e2e.sqlite3',SCANNER_ALLOW_PRIVATE:'0',SESSION_COOKIE_SECURE:'0',SYSTEM_ADMIN_EMAILS:'e2e-admin-chromium@example.com,e2e-admin-mobile-chromium@example.com'}
    },
    {
      command:'npm run dev -- --host 127.0.0.1',
      cwd:'.',
      port:5173,
      reuseExistingServer:false
    }
  ]
});
