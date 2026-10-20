import {test,expect} from '@playwright/test';

async function signup(page:any){
  await page.goto('/');
  await page.getByRole('link',{name:/Create secure workspace|Create workspace|Start workspace/}).first().click();
  await page.getByLabel('Full name').fill('Preflight Owner');
  await page.getByLabel('Workspace name').fill('Preflight Workspace');
  await page.getByLabel('Email address').fill('preflight-'+Date.now()+'@example.com');
  await page.getByLabel('Password').fill('preflight-secure-password-123');
  await page.getByRole('button',{name:'Create account'}).click();
  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
}
async function openNav(page:any,name:string){const menu=page.locator('button.menu');if(await menu.isVisible())await menu.click();await page.getByRole('button',{name,exact:true}).click()}

test('target setup preflight is visible before assessment',async({page})=>{
  await signup(page);
  await openNav(page,'Projects');
  await page.getByRole('button',{name:'New project'}).click();
  await page.getByLabel('Project name').fill('Preflight Project');
  await page.getByRole('button',{name:'Create project'}).click();

  await page.getByRole('button',{name:'Add target'}).click();
  await page.getByLabel('Display name').fill('Public Portal');
  await page.getByLabel('Target URL').fill('https://example.com/');
  await page.getByLabel(/I own this target/).check();
  await page.getByRole('dialog',{name:'Add authorised target'}).getByRole('button',{name:'Add target',exact:true}).click();
  await expect(page.getByText('Public Portal')).toBeVisible();

  const targetIdResponse=await page.request.get('/api/v1/targets');
  const targets=await targetIdResponse.json();
  const target=targets.find((x:any)=>x.name==='Public Portal');
  await page.route('**/api/v1/targets/'+target.id+'/preflight',async route=>{
    if(route.request().method()==='POST'){
      await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({
        id:'pf-test',target_id:target.id,profile:'standard',status:'READY',created_at:new Date().toISOString(),
        result:{status:'READY',requested_url:'https://example.com/',final_url:'https://example.com/',elapsed_ms:85,checks:[
          {key:'safe_destination',label:'Safe destination',status:'PASS',evidence:'Destination passed target-safety policy.'},
          {key:'reachability',label:'HTTP reachability',status:'PASS',evidence:'HTTP 200'},
          {key:'tls',label:'TLS handshake',status:'PASS',evidence:'TLSv1.3 · certificate valid'}
        ]}
      })});
    }else await route.continue();
  });

  await page.getByRole('button',{name:'Test setup'}).first().click();
  const dialog=page.getByRole('dialog',{name:'Target setup diagnostics'});
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button',{name:'Run preflight'}).click();
  await expect(dialog.getByText('Target setup is ready')).toBeVisible();
  await expect(dialog.getByText('TLS handshake')).toBeVisible();
});
