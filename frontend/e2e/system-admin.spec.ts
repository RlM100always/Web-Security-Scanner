import {test,expect} from '@playwright/test';

test('system admin can open global control center',async({page},testInfo)=>{
  const email='e2e-admin-'+testInfo.project.name+'@example.com';
  await page.goto('/signup');
  await page.getByRole('button',{name:'Create secure workspace'}).click();
  await page.getByLabel('Full name').fill('System Admin');
  await page.getByLabel('Workspace name').fill('Admin Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password',{exact:true}).fill('admin-secure-password-123');
  await page.getByLabel('Confirm password').fill('admin-secure-password-123');
  await page.getByRole('button',{name:'Create secure workspace'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
  await expect(page.getByText('System Administrator',{exact:true}).first()).toBeVisible();
  await expect(page.getByRole('button',{name:'Platform Admin'})).toBeVisible();

  await page.goto('/admin');
  await expect(page.getByRole('heading',{name:'Overview'})).toBeVisible();
  await expect(page.getByText('PLATFORM CONTROL CENTER')).toBeVisible();
  await page.getByRole('button',{name:'Users',exact:true}).click();
  await expect(page.getByText('Platform users')).toBeVisible();
  await expect(page.getByText('Global user directory')).toBeVisible();
  await expect(page.getByRole('button',{name:/Revoke sessions/}).first()).toBeVisible();
  await page.getByRole('button',{name:'Workspaces',exact:true}).click();
  await expect(page.getByText('All workspaces')).toBeVisible();
});
