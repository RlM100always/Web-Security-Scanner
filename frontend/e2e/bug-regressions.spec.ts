import {test,expect} from '@playwright/test';

async function signUp(page:any){
  const email='bugfix-'+Date.now()+'-'+Math.random().toString(16).slice(2)+'@example.com';
  await page.goto('/');
  await page.getByRole('link',{name:/Create secure workspace|Start workspace/i}).first().click();
  await page.getByLabel('Full name').fill('Regression Owner');
  await page.getByLabel('Workspace name').fill('Regression Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('regression-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
}

async function openWorkspaceNav(page:any,name:string){
  const dock=page.locator('.mobileDock');
  const dockButton=dock.getByRole('button',{name,exact:true});
  if(await dockButton.isVisible()){
    await dockButton.click();
    return;
  }
  const sideButton=page.locator('.side nav').getByRole('button',{name,exact:true});
  await sideButton.click();
}

test('unknown public path renders 404 instead of login',async({page})=>{
  await page.goto('/this-page-does-not-exist');
  await expect(page.getByRole('heading',{name:'This page does not exist.'})).toBeVisible();
  await expect(page.getByText('Welcome back')).toHaveCount(0);
});

test('secure account action without token gives a useful error',async({page})=>{
  await page.goto('/reset-password');
  await expect(page.getByRole('heading',{name:'Reset password'})).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('missing its token');
  await expect(page.getByRole('button',{name:'Continue'})).toHaveCount(0);
});

test('MFA management never renders a blank modal',async({page})=>{
  await signUp(page);
  await openWorkspaceNav(page,'Settings');
  await page.getByRole('button',{name:/Enable MFA|Manage MFA/}).click();
  await expect(page.getByRole('heading',{name:/Enable two-factor authentication|Manage two-factor authentication/})).toBeVisible();
  await expect(page.getByRole('button',{name:'Generate authenticator secret'})).toBeVisible();
});
