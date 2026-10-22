import {test,expect} from '@playwright/test';

async function noPageOverflow(page:any){
  const m=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,client:document.documentElement.clientWidth}));
  expect(m.scroll).toBeLessThanOrEqual(m.client+2);
}

test('public shell has no page-level horizontal overflow',async({page})=>{
  for(const path of ['/','/product','/enterprise','/vulnerability-management','/trust']){
    await page.goto(path);
    await page.waitForLoadState('domcontentloaded');
    await noPageOverflow(page);
  }
});

test('public layouts remain usable from 320px phones to wide desktops',async({page})=>{
  for(const width of [320,390,768,1024,1440]){
    await page.setViewportSize({width,height:900});
    for(const path of ['/','/enterprise','/vulnerability-management']){
      await page.goto(path);
      await page.waitForLoadState('domcontentloaded');
      await noPageOverflow(page);
      await expect(page.locator('.publicNav')).toBeVisible();
      await expect(page.getByRole('link',{name:'Skip to main content'})).toBeAttached();
    }
  }
});

test('authenticated shell switches between desktop and mobile navigation models',async({page},testInfo)=>{
  await page.goto('/');
  await page.getByRole('link',{name:/Create secure workspace|Create workspace|Start workspace/}).first().click();
  await page.getByLabel('Full name').fill('Responsive Owner');
  await page.getByLabel('Workspace name').fill('Responsive Workspace');
  await page.getByLabel('Email address').fill('responsive-'+testInfo.project.name+'-'+Date.now()+'@example.com');
  await page.getByLabel('Password',{exact:true}).fill('responsive-secure-password-123');
  await page.getByLabel('Confirm password').fill('responsive-secure-password-123');
  await page.getByRole('button',{name:'Create secure workspace'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
  await noPageOverflow(page);

  const width=page.viewportSize()?.width||1200;
  if(width<=820){
    await expect(page.locator('.mobileDock')).toBeVisible();
    await expect(page.locator('.side')).not.toBeInViewport();
    const buttons=page.locator('.mobileDock button');
    await expect(buttons).toHaveCount(5);
  }else{
    await expect(page.locator('.side')).toBeVisible();
    await expect(page.locator('.mobileDock')).toBeHidden();
    await expect(page.locator('.commandTrigger')).toBeVisible();
  }
});
