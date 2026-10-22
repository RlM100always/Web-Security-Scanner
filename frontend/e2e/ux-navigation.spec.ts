import {test,expect} from '@playwright/test';

test('workspace navigation, command search and mobile layout are user-friendly',async({page},testInfo)=>{
  const email='ux-'+testInfo.project.name+'-'+Date.now()+'@example.com';
  await page.goto('/signup');
  await page.getByLabel('Full name').fill('UX Test Owner');
  await page.getByLabel('Workspace name').fill('UX Review Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('ux-review-password-123');
  await page.getByRole('button',{name:'Create account'}).click();

  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Know what needs attention.'})).toBeVisible();
  await expect(page.locator('.dashboardIntro')).toBeVisible();

  if(testInfo.project.name==='mobile-chromium'){
    await expect(page.locator('.mobileDock')).toBeVisible();
    await page.getByRole('button',{name:'Open navigation'}).click();
    await expect(page.getByRole('button',{name:'Close navigation menu'})).toBeVisible();
    await page.getByRole('button',{name:'Close navigation menu'}).click();
    await expect(page.locator('.drawerScrim')).toHaveCount(0);
    await page.locator('.mobileDock').getByRole('button',{name:'Issues'}).click();
    await expect(page).toHaveURL(/#\/issues$/);
    await page.goBack();
    await expect(page.getByRole('heading',{name:'Know what needs attention.'})).toBeVisible();
  }else{
    await page.locator('aside.side').getByRole('button',{name:'Projects',exact:true}).click();
    await expect(page).toHaveURL(/#\/projects$/);
    await page.goBack();
    await expect(page.getByRole('heading',{name:'Know what needs attention.'})).toBeVisible();
  }

  await page.getByRole('button',{name:'Search pages, projects, targets and issues'}).click();
  await expect(page.getByRole('textbox',{name:'Command search'})).toBeVisible();
  await page.getByRole('textbox',{name:'Command search'}).fill('issues');
  await expect(page.getByRole('button',{name:/Issues/}).last()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('textbox',{name:'Command search'})).toHaveCount(0);

  const dimensions=await page.evaluate(()=>({viewport:window.innerWidth,document:document.documentElement.scrollWidth}));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport+1);
});
