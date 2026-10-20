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

  await page.goto('/signup');
  await expect(page.getByRole('heading',{name:/Start your security workspace/i})).toBeVisible();
});

test('public navigation remains usable on mobile',async({page},testInfo)=>{
  test.skip(!testInfo.project.name.includes('mobile'),'mobile-only navigation check');
  await page.goto('/');
  await page.getByRole('button',{name:'Toggle navigation'}).click();
  await page.locator('.publicNav nav').getByRole('link',{name:'Solutions',exact:true}).click();
  await expect(page).toHaveURL(/\/solutions$/);
  await expect(page.getByRole('heading',{name:/practical security workspace/i})).toBeVisible();
});
