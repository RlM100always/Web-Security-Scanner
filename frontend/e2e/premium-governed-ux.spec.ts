import {test,expect} from '@playwright/test';

async function signup(page:any){
  await page.goto('/');
  await page.getByRole('link',{name:/Start workspace|Create workspace/}).first().click();
  await page.getByLabel('Full name').fill('Governed UX Owner');
  await page.getByLabel('Workspace name').fill('Governed UX');
  await page.getByLabel('Email address').fill('governed-'+Date.now()+'@example.com');
  await page.getByLabel('Password').fill('governed-secure-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
}

test('public product story exposes trust and role journeys',async({page})=>{
  await page.goto('/');
  await expect(page.getByText('Authorised assessment only')).toBeVisible();
  await expect(page.getByText('One platform, different jobs to be done.')).toBeVisible();
  await expect(page.getByRole('link',{name:/Explore governance/i})).toBeVisible();
  await expect(page.getByRole('link',{name:/Live platform status/i})).toBeVisible();
});

test('permanent project deletion requires an in-product typed confirmation',async({page})=>{
  await signup(page);
  const menu=page.locator('button.menu');
  if(await menu.isVisible())await menu.click();
  await page.getByRole('button',{name:'Projects',exact:true}).click();
  await page.getByRole('button',{name:'New project'}).click();
  await page.getByLabel('Project name').fill('Disposable Project');
  await page.getByRole('button',{name:'Create project'}).click();
  await expect(page.getByText('Disposable Project')).toBeVisible();

  await page.getByRole('button',{name:'Delete project'}).click();
  const dialog=page.getByRole('dialog',{name:/Permanently delete project/i});
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText(/cannot be undone/i)).toBeVisible();
  await expect(dialog.getByRole('button',{name:'Permanently delete'})).toBeDisabled();
  await dialog.getByPlaceholder('DELETE').fill('DELETE');
  await expect(dialog.getByRole('button',{name:'Permanently delete'})).toBeEnabled();
  await dialog.getByRole('button',{name:'Permanently delete'}).click();
  await expect(page.getByText('Disposable Project')).toHaveCount(0);
});
