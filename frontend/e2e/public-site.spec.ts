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

  await page.goto('/signup');
  await expect(page.getByRole('heading',{name:/Start your security workspace/i})).toBeVisible();
});

test('public navigation remains usable on mobile',async({page},testInfo)=>{
  test.skip(!testInfo.project.name.includes('mobile'),'mobile-only navigation check');
  await page.goto('/');
  await page.getByRole('button',{name:'Toggle navigation'}).click();
  await page.getByRole('link',{name:'Features',exact:true}).click();
  await expect(page).toHaveURL(/\/features$/);
  await expect(page.getByRole('heading',{name:/Depth across identity/i})).toBeVisible();
});
