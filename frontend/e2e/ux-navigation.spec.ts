import {test,expect} from '@playwright/test';

test('workspace navigation, command search and mobile layout are user-friendly',async({page},testInfo)=>{
  const email='ux-'+testInfo.project.name+'-'+Date.now()+'@example.com';
  await page.goto('/signup');
  await page.getByLabel('Full name').fill('UX Test Owner');
  await page.getByLabel('Workspace name').fill('UX Review Workspace');
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Password',{exact:true}).fill('ux-review-password-123');
  await page.getByLabel('Confirm password').fill('ux-review-password-123');
  await page.getByRole('button',{name:'Create secure workspace'}).click();

  await expect(page.getByRole('heading',{name:'Dashboard'})).toBeVisible();
  await expect(page).toHaveTitle('Dashboard | SentinelScope');
  await expect(page.getByRole('heading',{name:'Know what needs attention.'})).toBeVisible();
  await expect(page.locator('.dashboardIntro')).toBeVisible();
  await expect(page.getByText('Workspace Owner',{exact:true}).first()).toBeVisible();
  const guideButton=testInfo.project.name==='mobile-chromium'
    ? page.locator('.mobileDock').getByRole('button',{name:'Guide',exact:true})
    : page.locator('aside.side').getByRole('button',{name:'Guide',exact:true});
  await guideButton.click();
  await expect(page.getByRole('heading',{name:'From authorised scope to verified remediation.'})).toBeVisible();
  await expect(page.getByText('Where to go for each job')).toBeVisible();
  await page.locator('.guidePanelMap').getByRole('button',{name:/Manage your account/}).click();
  await expect(page.getByRole('heading',{name:'Settings',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Edit profile'}).click();
  await page.getByLabel('Display name').fill('UX Test Owner Updated');
  await page.getByRole('button',{name:'Save profile'}).click();
  await expect(page.getByText('UX Test Owner Updated',{exact:true}).first()).toBeVisible();
  await page.locator('.appearanceChoice button').nth(1).click();
  await expect.poll(async()=>page.evaluate(()=>document.documentElement.dataset.theme)).toBe('dark');
  await expect(page.locator('.settingsGrid .panel').first()).toHaveCSS('background-color',/rgb/);
  await page.locator('.appearanceChoice button').nth(0).click();
  await expect.poll(async()=>page.evaluate(()=>document.documentElement.dataset.theme)).toBe('light');
  if(testInfo.project.name==='mobile-chromium') await page.locator('.mobileDock').getByRole('button',{name:'Dashboard',exact:true}).click();
  else await page.locator('aside.side').getByRole('button',{name:'Dashboard',exact:true}).click();

  const visual=await page.evaluate(()=> {
    const intro=document.querySelector('.dashboardIntro') as HTMLElement|null;
    const side=document.querySelector('.side') as HTMLElement|null;
    const score=document.querySelector('.dashboardScoreCard') as HTMLElement|null;
    const dock=document.querySelector('.mobileDock') as HTMLElement|null;
    return {
      introRadius:intro?parseFloat(getComputedStyle(intro).borderRadius):0,
      sideWidth:side?.getBoundingClientRect().width||0,
      scoreBg:score?getComputedStyle(score).backgroundColor:'',
      dockRadius:dock?parseFloat(getComputedStyle(dock).borderRadius):0
    };
  });
  expect(visual.introRadius).toBeGreaterThanOrEqual(18);
  expect(visual.scoreBg).not.toBe('rgba(0, 0, 0, 0)');
  if(testInfo.project.name==='mobile-chromium') expect(visual.dockRadius).toBeGreaterThanOrEqual(16);
  else expect(visual.sideWidth).toBeGreaterThanOrEqual(220);

  const skip=page.getByRole('link',{name:'Skip to main content'});
  await expect(skip).toBeAttached();
  await skip.focus();
  await expect(skip).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#workspace-content')).toBeFocused();

  if(testInfo.project.name==='mobile-chromium'){
    await expect(page.locator('.mobileDock')).toBeVisible();
    await page.getByRole('button',{name:'Open navigation'}).click();
    await expect(page.getByRole('button',{name:'Close navigation menu'})).toBeVisible();
    await expect(page.getByRole('button',{name:'Open navigation'})).toHaveAttribute('aria-expanded','true');
    await page.keyboard.press('Shift+Tab');
    await expect(page.locator('#workspace-nav').getByRole('button',{name:'Settings',exact:true})).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button',{name:'Close navigation menu'})).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('button',{name:'Open navigation'})).toHaveAttribute('aria-expanded','false');
    await expect(page.locator('.drawerScrim')).toHaveCount(0);
    await page.locator('.mobileDock').getByRole('button',{name:'Issues'}).click();
    await expect(page).toHaveURL(/#\/issues$/);
    await page.goBack();
    await expect(page.getByRole('heading',{name:'Know what needs attention.'})).toBeVisible();
  }else{
    await page.locator('aside.side').getByRole('button',{name:'Projects',exact:true}).click();
    await expect(page).toHaveURL(/#\/projects$/);
    await page.goBack();
    await expect(page.getByRole('heading',{name:'Know what needs attention.'})).toBeVisible();
  }

  await page.getByRole('button',{name:'Search pages, projects, targets and issues'}).click();
  await expect(page.getByRole('textbox',{name:'Command search'})).toBeVisible();
  await page.getByRole('textbox',{name:'Command search'}).fill('issues');
  await expect(page.getByRole('button',{name:/Issues/}).last()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('textbox',{name:'Command search'})).toHaveCount(0);

  const dimensions=await page.evaluate(()=>({viewport:window.innerWidth,document:document.documentElement.scrollWidth}));
  expect(dimensions.document).toBeLessThanOrEqual(dimensions.viewport+1);
});
