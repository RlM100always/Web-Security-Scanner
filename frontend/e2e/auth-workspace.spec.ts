import {test,expect} from '@playwright/test';

test('signup opens authenticated workspace and creates a project',async({page})=>{
  const email='e2e-'+Date.now()+'@example.com';
  await page.goto('/signup');
  await page.getByRole('button',{name:'Create account'}).click();
  await page.getByLabel('Full name').fill('E2E Owner');
  await page.getByLabel('Workspace name').fill('E2E Security');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('e2e-secure-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
  const menu=page.locator('button.menu');
  if(await menu.isVisible()) await menu.click();
  await page.getByRole('button',{name:'Projects',exact:true}).click();
  await page.getByRole('button',{name:'New project'}).click();
  await page.getByLabel('Project name').fill('E2E Web Estate');
  await page.getByLabel('Description').fill('Browser integration test');
  await page.getByRole('button',{name:'Create project',exact:true}).click();
  await expect(page.getByText('E2E Web Estate')).toBeVisible();
});
