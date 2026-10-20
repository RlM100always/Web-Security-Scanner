import {test,expect} from '@playwright/test';

async function openNav(page:any,name:string){
  const menu=page.locator('button.menu');
  if(await menu.isVisible()){
    await menu.click();
    await page.locator('aside.side').getByRole('button',{name,exact:true}).click();
  }else{
    await page.locator('aside.side').getByRole('button',{name,exact:true}).click();
  }
}

test('deep scan policy and API key workflow works',async({page},testInfo)=>{
  const email='deep-'+testInfo.project.name+'-'+Date.now()+'@example.com';

  await page.goto('/signup');
  await page.getByLabel('Full name').fill('Deep Feature Owner');
  await page.getByLabel('Workspace name').fill('Deep Feature Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('deep-feature-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
  await expect(page.getByText('WORKSPACE READINESS')).toBeVisible();

  await openNav(page,'Projects');
  await page.getByRole('button',{name:'New project'}).click();
  await page.getByLabel('Project name').fill('Production Estate');
  await page.getByLabel('Description').fill('Policy managed estate');
  await page.getByRole('button',{name:'Create project',exact:true}).click();
  await expect(page.getByText('Production Estate')).toBeVisible();

  const projectCard=page.locator('.projectCard').filter({hasText:'Production Estate'});
  await projectCard.getByRole('button',{name:'Scan profiles'}).click();
  await expect(page.getByText('Govern assessment configuration once, reuse it everywhere.')).toBeVisible();
  await expect(page.getByRole('heading',{name:'Standard Baseline',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Create scan profile'}).click();
  await page.getByLabel('Profile name').fill('Release Gate');
  await page.getByLabel('Description').fill('Release readiness profile');
  await page.getByLabel('Maximum pages').fill('22');
  await page.getByRole('button',{name:'Create profile',exact:true}).click();
  await expect(page.getByText('Release Gate')).toBeVisible();
  await expect(page.getByText('v1 · 22 pages · depth 2')).toBeVisible();
  await page.locator('.modalHead button').click();

  await projectCard.getByRole('button',{name:'Base policy'}).click();
  await page.getByLabel('Maximum pages').fill('37');
  await page.getByLabel('Maximum crawl depth').fill('3');
  await page.getByLabel('Request delay (ms)').fill('250');
  await page.getByLabel('Exclude path regex — one per line').fill('^/logout$\n^/billing/export');
  await Promise.all([
    page.waitForResponse(r=>r.url().includes('/policy')&&r.request().method()==='PUT'&&r.status()===200),
    page.getByRole('button',{name:'Save policy'}).click()
  ]);
  await expect(page.getByText('Scan policy saved')).toBeVisible();

  await Promise.all([
    page.waitForResponse(r=>r.url().includes('/policy')&&r.request().method()==='GET'&&r.status()===200),
    projectCard.getByRole('button',{name:'Base policy'}).click()
  ]);
  await expect(page.getByLabel('Maximum pages')).toHaveValue('37');
  const persistedExclude=await page.getByLabel('Exclude path regex — one per line').inputValue();
  expect(persistedExclude.split(String.fromCharCode(10))).toEqual(['^/logout$','^/billing/export']);
  await page.getByRole('button',{name:'Cancel'}).click();

  await openNav(page,'Settings');
  await page.getByRole('button',{name:'New API key'}).click();
  await page.getByLabel('Key name').fill('CI Integration');
  await page.getByLabel('Expires in days').fill('30');
  await page.getByRole('button',{name:'Create key'}).click();
  await expect(page.locator('.codeBox')).toContainText('wss_');
});
