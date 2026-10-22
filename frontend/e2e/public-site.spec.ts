import {test,expect} from '@playwright/test';

test('public product site explains platform and routes to signup',async({page})=>{
  await page.goto('/');
  await expect(page.getByRole('heading',{name:/Turn web-security checks/i})).toBeVisible();
  await expect(page.getByText('OWASP WSTG')).toBeVisible();
  await expect(page.getByRole('link',{name:/Create secure workspace/i})).toBeVisible();

  await page.goto('/security');
  await expect(page.getByRole('heading',{name:/Safe-by-default behaviour/i})).toBeVisible();
  await expect(page.getByText(/SSRF and scope controls/i)).toBeVisible();

  await page.goto('/standards');
  await expect(page.getByRole('heading',{name:/Evidence is mapped to controls/i})).toBeVisible();

  await page.goto('/docs');
  await expect(page.getByRole('heading',{name:/Understand how the platform behaves/i})).toBeVisible();

  await page.goto('/enterprise');
  await expect(page.getByRole('heading',{name:/Govern security work/i})).toBeVisible();
  await expect(page.getByText(/Governed issue operations/i)).toBeVisible();

  await page.goto('/workflow');
  await expect(page.getByRole('heading',{name:/authorised scope to verified remediation/i})).toBeVisible();

  await page.goto('/research');
  await expect(page.getByRole('heading',{name:/scanner claims can be measured/i})).toBeVisible();

  await page.goto('/responsible-use');
  await expect(page.getByRole('heading',{name:/Authorisation and bounded behaviour/i})).toBeVisible();

  await page.goto('/deployment');
  await expect(page.getByRole('heading',{name:/single-node architecture/i})).toBeVisible();

  await page.goto('/trust');
  await expect(page.getByRole('heading',{name:/Security boundaries, operational controls/i})).toBeVisible();

  await page.goto('/integrations');
  await expect(page.getByRole('heading',{name:/Connect security events/i})).toBeVisible();

  await page.goto('/developers');
  await expect(page.getByRole('heading',{name:/Build controlled automation/i})).toBeVisible();

  await page.goto('/architecture');
  await expect(page.getByRole('heading',{name:/modular single-node architecture/i})).toBeVisible();

  await page.goto('/scanner-checks');
  await expect(page.getByRole('heading',{name:/Transparent checks with evidence/i})).toBeVisible();

  await page.goto('/reports');
  await expect(page.getByRole('heading',{name:/Reports that preserve the context/i})).toBeVisible();

  await page.goto('/asset-inventory');
  await expect(page.getByRole('heading',{name:/Know what was actually discovered/i})).toBeVisible();

  await page.goto('/scan-profiles');
  await expect(page.getByRole('heading',{name:/Reusable, versioned scan profiles/i})).toBeVisible();

  await page.goto('/vulnerability-management');
  await expect(page.getByRole('heading',{name:/Treat findings as owned security work/i})).toBeVisible();

  await page.goto('/continuous-monitoring');
  await expect(page.getByRole('heading',{name:/Repeat the same governed assessment/i})).toBeVisible();

  await page.goto('/governance');
  await expect(page.getByRole('heading',{name:/Separate workspace decisions/i})).toBeVisible();

  await page.goto('/getting-started');
  await expect(page.getByRole('heading',{name:/empty workspace to a trustworthy first baseline/i})).toBeVisible();

  await page.goto('/methodology');
  await expect(page.getByRole('heading',{name:/What the scanner measures/i})).toBeVisible();

  await page.goto('/status');
  await expect(page.getByRole('heading',{name:/Operational transparency/i})).toBeVisible();
  await expect(page.getByText(/All public platform checks operational/i)).toBeVisible();

  await page.goto('/signup');
  await expect(page.getByRole('heading',{name:/Start your security workspace/i})).toBeVisible();
});

test('public navigation remains usable and keyboard accessible on mobile',async({page},testInfo)=>{
  test.skip(!testInfo.project.name.includes('mobile'),'mobile-only navigation check');
  await page.goto('/');

  const skip=page.getByRole('link',{name:'Skip to main content'});
  await expect(skip).toHaveCount(1);
  await page.keyboard.press('Tab');
  await expect(skip).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();

  const menu=page.getByRole('button',{name:'Toggle navigation'});
  await expect(menu).toHaveAttribute('aria-expanded','false');
  await expect(menu).toHaveAttribute('aria-controls','public-primary-nav');
  await menu.click();
  await expect(menu).toHaveAttribute('aria-expanded','true');
  await page.keyboard.press('Escape');
  await expect(menu).toHaveAttribute('aria-expanded','false');
  await expect(menu).toBeFocused();

  await menu.click();
  await expect(menu).toHaveAttribute('aria-expanded','true');
  await page.locator('.publicNav nav').getByRole('link',{name:'Solutions',exact:true}).click();
  await expect(page).toHaveURL(/\\/solutions$/);
  await expect(page.getByRole('heading',{name:/practical security workspace/i})).toBeVisible();
});;


test('public exposure management page explains contextual workflow',async({page})=>{
  await page.goto('/exposure-management');
  await expect(page.getByRole('heading',{name:/Connect governed scope/i})).toBeVisible();
  await expect(page.getByText(/Relationship map/i).first()).toBeVisible();
  await expect(page.getByText(/Contextual prioritisation/i).first()).toBeVisible();
});
