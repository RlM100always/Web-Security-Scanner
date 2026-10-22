import {test,expect} from '@playwright/test';

async function openNav(page:any,name:string){
  const menu=page.locator('button.menu');
  if(await menu.isVisible())await menu.click();
  await page.locator('aside.side').getByRole('button',{name,exact:true}).click();
}

test('enterprise integrations and access certification work',async({page},testInfo)=>{
  const email='enterprise-'+testInfo.project.name+'-'+Date.now()+'@example.com';
  await page.goto('/signup');
  await page.getByLabel('Full name').fill('Enterprise Owner');
  await page.getByLabel('Workspace name').fill('Enterprise Security');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password',{exact:true}).fill('enterprise-owner-password-123');
  await page.getByLabel('Confirm password').fill('enterprise-owner-password-123');
  await page.getByRole('button',{name:'Create secure workspace'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();

  await openNav(page,'Integrations');
  await expect(page.getByRole('heading',{name:'Outbound webhooks'})).toBeVisible();
  await page.getByRole('button',{name:'New webhook'}).click();
  await page.getByLabel('Integration name').fill('Security automation');
  await page.getByLabel('HTTPS endpoint').fill('https://example.com/sentinelscope-hook');
  await page.getByRole('button',{name:'Create integration'}).click();
  await expect(page.getByText('Copy the signing secret now')).toBeVisible();
  await expect(page.locator('.codeBox')).toContainText('whsec_');
  await page.getByRole('button',{name:'Copy secret & finish'}).click();
  await expect(page.getByText('Security automation')).toBeVisible();

  await openNav(page,'Team');
  await page.getByRole('button',{name:'Start access review'}).click();
  await expect(page.getByText('ACCESS CERTIFICATION')).toBeVisible();
  await page.getByRole('button',{name:'Confirm owner'}).click();
  await expect(page.getByText('APPROVE',{exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Complete review'}).click();
  await expect(page.locator('.accessReviewRow').first().getByText('COMPLETED',{exact:true})).toBeVisible();
});
