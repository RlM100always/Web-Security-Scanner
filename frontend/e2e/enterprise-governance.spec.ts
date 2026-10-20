import {test,expect} from '@playwright/test';

async function openNav(page:any,name:string){
  const menu=page.locator('button.menu');
  if(await menu.isVisible())await menu.click();
  await page.locator('aside.side').getByRole('button',{name,exact:true}).click();
}

test('workspace remediation governance persists on desktop and mobile',async({page},testInfo)=>{
  const email='governance-'+testInfo.project.name+'-'+Date.now()+'@example.com';
  await page.goto('/signup');
  await page.getByLabel('Full name').fill('Governance Owner');
  await page.getByLabel('Workspace name').fill('Security Operations');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password').fill('governance-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();

  await openNav(page,'Settings');
  await expect(page.getByText('Remediation governance')).toBeVisible();
  await page.getByLabel('HIGH SLA days').fill('11');
  await page.getByText('Owner approval for accepted risk').click();
  await Promise.all([
    page.waitForResponse(r=>r.url().includes('/workspace/security-policy')&&r.request().method()==='PUT'&&r.status()===200),
    page.getByRole('button',{name:'Save remediation policy'}).click()
  ]);
  await expect(page.getByText('Workspace remediation policy saved')).toBeVisible();

  await openNav(page,'Dashboard');
  await openNav(page,'Settings');
  await expect(page.getByLabel('HIGH SLA days')).toHaveValue('11');
  const ownerApproval=page.getByText('Owner approval for accepted risk').locator('..').getByRole('checkbox');
  await expect(ownerApproval).toBeChecked();
});
