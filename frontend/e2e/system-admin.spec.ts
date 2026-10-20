import {test,expect} from '@playwright/test';

test('system admin can open global control center',async({page},testInfo)=>{
  const email='e2e-admin-'+testInfo.project.name+'@example.com';
  await page.goto('/signup');
  await page.getByRole('button',{name:'Create account'}).click();
  await page.getByLabel('Full name').fill('System Admin');
  await page.getByLabel('Workspace name').fill('Admin Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('admin-secure-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();

  await page.goto('/admin');
  await expect(page.getByRole('heading',{name:'Overview'})).toBeVisible();
  await expect(page.getByText('PLATFORM CONTROL CENTER')).toBeVisible();
  await page.getByRole('button',{name:'Users',exact:true}).click();
  await expect(page.getByText('Global user directory')).toBeVisible();
  await page.getByRole('button',{name:'Workspaces',exact:true}).click();
  await expect(page.getByText('All workspaces')).toBeVisible();
});
