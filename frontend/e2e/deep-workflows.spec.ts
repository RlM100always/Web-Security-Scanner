import {test,expect} from '@playwright/test';

async function openNav(page:any,name:string){
  const menu=page.locator('button.menu');
  if(await menu.isVisible())await menu.click();
  await page.getByRole('button',{name,exact:true}).click();
}

test('deep scan policy and API key workflow works',async({page},testInfo)=>{
  const email='deep-'+testInfo.project.name+'-'+Date.now()+'@example.com';
  await page.goto('/');
  await page.getByRole('button',{name:'Create account'}).click();
  await page.getByLabel('Full name').fill('Deep Feature Owner');
  await page.getByLabel('Workspace name').fill('Deep Feature Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('deep-feature-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();

  await openNav(page,'Projects');
  await page.getByRole('button',{name:'New project'}).click();
  await page.getByLabel('Project name').fill('Production Estate');
  await page.getByLabel('Description').fill('Policy managed estate');
  await page.getByRole('button',{name:'Create',exact:true}).click();
  await expect(page.getByText('Production Estate')).toBeVisible();

  await page.getByRole('button',{name:'Scan policy'}).click();
  const pages=page.getByLabel('Maximum pages');
  await pages.fill('37');
  await page.getByLabel('Maximum crawl depth').fill('3');
  await page.getByLabel('Request delay (ms)').fill('250');
  await page.getByLabel('Exclude path regex — one per line').fill('^/logout$\n^/billing/export');
  await page.getByRole('button',{name:'Save policy'}).click();
  await expect(page.getByText('Scan policy saved')).toBeVisible();

  await page.getByRole('button',{name:'Scan policy'}).click();
  await expect(page.getByLabel('Maximum pages')).toHaveValue('37');
  const persistedExclude=await page.getByLabel('Exclude path regex — one per line').inputValue();
  expect(persistedExclude.split('\n')).toEqual(['^/logout
  await page.getByRole('button',{name:'Cancel'}).click();

  await openNav(page,'Settings');
  await page.getByRole('button',{name:'New API key'}).click();
  await page.getByLabel('Key name').fill('CI Integration');
  await page.getByLabel('Expires in days').fill('30');
  await page.getByRole('button',{name:'Create key'}).click();
  await expect(page.locator('.codeBox')).toContainText('wss_');
});
,'^/billing/export']);
  await page.getByRole('button',{name:'Cancel'}).click();

  await openNav(page,'Settings');
  await page.getByRole('button',{name:'New API key'}).click();
  await page.getByLabel('Key name').fill('CI Integration');
  await page.getByLabel('Expires in days').fill('30');
  await page.getByRole('button',{name:'Create key'}).click();
  await expect(page.locator('.codeBox')).toContainText('wss_');
});
