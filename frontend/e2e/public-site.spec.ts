import {test,expect} from '@playwright/test';

test('public product site explains platform and routes to signup',async({page})=>{
  await page.goto('/');
  await expect(page).toHaveTitle(/SentinelScope — Web Security Assessment Platform/);
  await expect(page.getByRole('heading',{name:/Turn web-security checks/i})).toBeVisible();
  await expect(page.getByText('OWASP WSTG')).toBeVisible();
  await expect(page.locator('.redesignedHero .heroCtas').getByRole('link',{name:/Start workspace/i})).toBeVisible();
  await expect(page.locator('.redesignedHero .heroVisual')).toBeVisible();
  await expect(page.getByRole('heading',{name:/A security assessment becomes useful/i})).toBeVisible();
  await expect(page.locator('.homeModuleCard')).toHaveCount(3);
  await expect(page.locator('.evidenceLifecycleRail article')).toHaveCount(5);
  await expect(page.locator('.workflowCompareSection')).toBeVisible();
  const firstFaq=page.locator('.publicFaqItem').first();
  await firstFaq.locator('summary').click();
  await expect(firstFaq).toHaveAttribute('open','');

  await page.goto('/security');
  await expect(page.getByRole('heading',{name:/Safe-by-default behaviour/i})).toBeVisible();
  await expect(page.getByText(/SSRF and scope controls/i)).toBeVisible();

  await page.goto('/standards');
  await expect(page.getByRole('heading',{name:/Evidence is mapped to controls/i})).toBeVisible();

  await page.goto('/docs');
  await expect(page.getByRole('heading',{name:/Understand how the platform behaves/i})).toBeVisible();

  await page.goto('/enterprise');
  await expect(page.getByRole('heading',{name:/Govern security work/i})).toBeVisible();
  await expect(page.getByText(/Governed issue operations/i)).toBeVisible();

  await page.goto('/workflow');
  await expect(page.getByRole('heading',{name:/authorised scope to verified remediation/i})).toBeVisible();

  await page.goto('/research');
  await expect(page.getByRole('heading',{name:/scanner claims can be measured/i})).toBeVisible();

  await page.goto('/responsible-use');
  await expect(page.getByRole('heading',{name:/Authorisation and bounded behaviour/i})).toBeVisible();

  await page.goto('/deployment');
  await expect(page.getByRole('heading',{name:/single-node architecture/i})).toBeVisible();

  await page.goto('/trust');
  await expect(page.getByRole('heading',{name:/Security boundaries, operational controls/i})).toBeVisible();

  await page.goto('/integrations');
  await expect(page.getByRole('heading',{name:/Connect security events/i})).toBeVisible();

  await page.goto('/developers');
  await expect(page.getByRole('heading',{name:/Build controlled automation/i})).toBeVisible();

  await page.goto('/architecture');
  await expect(page.getByRole('heading',{name:/modular single-node architecture/i})).toBeVisible();

  await page.goto('/scanner-checks');
  await expect(page.getByRole('heading',{name:/Transparent checks with evidence/i})).toBeVisible();

  await page.goto('/reports');
  await expect(page.getByRole('heading',{name:/Reports that preserve the context/i})).toBeVisible();

  await page.goto('/asset-inventory');
  await expect(page.getByRole('heading',{name:/Know what was actually discovered/i})).toBeVisible();

  await page.goto('/scan-profiles');
  await expect(page.getByRole('heading',{name:/Reusable, versioned scan profiles/i})).toBeVisible();

  await page.goto('/vulnerability-management');
  await expect(page.getByRole('heading',{name:/Treat findings as owned security work/i})).toBeVisible();

  await page.goto('/continuous-monitoring');
  await expect(page.getByRole('heading',{name:/Repeat the same governed assessment/i})).toBeVisible();

  await page.goto('/governance');
  await expect(page.getByRole('heading',{name:/Separate workspace decisions/i})).toBeVisible();

  await page.goto('/getting-started');
  await expect(page.getByRole('heading',{name:/empty workspace to a trustworthy first baseline/i})).toBeVisible();

  await page.goto('/methodology');
  await expect(page.getByRole('heading',{name:/What the scanner measures/i})).toBeVisible();

  await page.goto('/status');
  await expect(page.getByRole('heading',{name:/Operational transparency/i})).toBeVisible();
  await expect(page.getByText(/All public platform checks operational/i)).toBeVisible();

  await page.goto('/signup');
  await expect(page.getByRole('heading',{name:/Start your security workspace/i})).toBeVisible();
});

test('public navigation remains usable and keyboard accessible on mobile',async({page},testInfo)=>{
  test.skip(!testInfo.project.name.includes('mobile'),'mobile-only navigation check');
  await page.goto('/');

  const skip=page.getByRole('link',{name:'Skip to main content'});
  await expect(skip).toHaveCount(1);
  await page.keyboard.press('Tab');
  await expect(skip).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();

  const menu=page.getByRole('button',{name:'Toggle navigation'});
  await expect(menu).toHaveAttribute('aria-expanded','false');
  await expect(menu).toHaveAttribute('aria-controls','public-primary-nav');
  await menu.click();
  await expect(menu).toHaveAttribute('aria-expanded','true');
  await page.keyboard.press('Escape');
  await expect(menu).toHaveAttribute('aria-expanded','false');
  await expect(menu).toBeFocused();

  await menu.click();
  await expect(menu).toHaveAttribute('aria-expanded','true');
  await page.locator('.publicNav nav').getByRole('link',{name:'Solutions',exact:true}).click();
  await expect(page).toHaveURL(/\/solutions$/);
  await expect(page.getByRole('heading',{name:/practical security workspace/i})).toBeVisible();
});


test('public exposure management page explains contextual workflow',async({page})=>{
  await page.goto('/exposure-management');
  await expect(page.getByRole('heading',{name:/Connect governed scope/i})).toBeVisible();
  await expect(page.getByText(/Relationship map/i).first()).toBeVisible();
  await expect(page.getByText(/Contextual prioritisation/i).first()).toBeVisible();
});

test('public site mobile layout keeps header, detail hero and footer aligned to the left edge',async({page})=>{
  for(const width of [320,390,430,768]){
    await page.setViewportSize({width,height:900});
    for(const path of ['/product','/developers','/enterprise']){
      await page.goto(path);
      const layout=await page.evaluate(()=>({
        viewport:document.documentElement.clientWidth,
        document:document.documentElement.scrollWidth,
        headerLeft:document.querySelector('.publicNav')?.getBoundingClientRect().left??999,
        brandLeft:document.querySelector('.publicNav .publicBrand')?.getBoundingClientRect().left??999,
        heroLeft:document.querySelector('.pageHeroVisual')?.getBoundingClientRect().left??999,
        copyLeft:document.querySelector('.pageHeroCopy')?.getBoundingClientRect().left??999,
        footerLeft:document.querySelector('.publicFooter')?.getBoundingClientRect().left??999,
        heroWidth:document.querySelector('.pageHeroVisual')?.getBoundingClientRect().width??0
      }));
      expect(layout.document).toBeLessThanOrEqual(layout.viewport+2);
      expect(layout.headerLeft).toBeLessThanOrEqual(1);
      expect(layout.brandLeft).toBeLessThanOrEqual(25);
      expect(layout.heroLeft).toBeLessThanOrEqual(1);
      expect(layout.copyLeft).toBeLessThanOrEqual(30);
      expect(layout.footerLeft).toBeLessThanOrEqual(1);
      expect(layout.heroWidth).toBeGreaterThan(0);
    }
  }
});

test('public detail pages use a balanced visual hero instead of an empty side column',async({page})=>{
  const paths=['/product','/features','/solutions','/enterprise','/developers','/docs','/security','/trust','/status','/standards','/workflow','/exposure-management','/asset-inventory','/scan-profiles','/vulnerability-management','/continuous-monitoring','/governance','/getting-started','/methodology','/research','/reports','/integrations','/deployment','/architecture','/scanner-checks','/responsible-use'];
  for(const path of paths){
    await page.goto(path);
    await expect(page.locator('.pageHeroVisual')).toBeVisible();
    await expect(page.locator('.pageHeroCopy h1')).toBeVisible();
    await expect(page.locator('.pageVisual')).toBeVisible();
    const dimensions=await page.evaluate(()=>({
      hero:document.querySelector('.pageHeroVisual')?.getBoundingClientRect().width||0,
      copy:document.querySelector('.pageHeroCopy')?.getBoundingClientRect().width||0,
      visual:document.querySelector('.pageVisual')?.getBoundingClientRect().width||0,
      scroll:document.documentElement.scrollWidth,
      client:document.documentElement.clientWidth
    }));
    expect(dimensions.hero).toBeGreaterThan(0);
    expect(dimensions.copy).toBeGreaterThan(0);
    expect(dimensions.visual).toBeGreaterThan(dimensions.hero*0.35);
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client+2);
  }
});

test('login, signup and account action pages have branded responsive visual panels',async({page})=>{
  for(const width of [320,390,768,1024,1440]){
    await page.setViewportSize({width,height:900});
    for(const path of ['/login','/signup','/verify-email','/reset-password','/accept-invite']){
      await page.goto(path);
      await expect(page.locator('.authExperience')).toBeVisible();
      await expect(page.locator('.authBrand')).toBeVisible();
      await expect(page.locator('.authVisualCard')).toBeVisible();
      await expect(page.locator('.authCardExperience')).toBeVisible();
      const dimensions=await page.evaluate(()=>({scroll:document.documentElement.scrollWidth,client:document.documentElement.clientWidth,brand:document.querySelector('.authBrand')?.getBoundingClientRect().width||0,card:document.querySelector('.authCardExperience')?.getBoundingClientRect().width||0}));
      expect(dimensions.brand).toBeGreaterThan(0);
      expect(dimensions.card).toBeGreaterThan(0);
      expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.client+2);
    }
  }
});

test('signup password controls, matching validation and trusted-device choice work',async({page})=>{
  await page.goto('/signup');
  const password=page.getByPlaceholder('12+ characters');
  const confirmation=page.getByPlaceholder('Re-enter your password');
  await password.fill('unique-demo-passphrase-123');
  await confirmation.fill('different-demo-passphrase-456');
  await expect(page.locator('.authSubmit')).toBeDisabled();
  await expect(page.getByText('Passwords do not match yet.')).toBeVisible();
  await confirmation.fill('unique-demo-passphrase-123');
  await expect(page.locator('.authSubmit')).toBeEnabled();
  await page.locator('.authPasswordToggle').first().click();
  await expect(password).toHaveAttribute('type','text');
  await page.locator('.authPasswordToggle').first().click();
  await expect(password).toHaveAttribute('type','password');

  await page.goto('/login');
  const remember=page.getByRole('checkbox',{name:/Keep me signed in for 30 days/i});
  await expect(remember).not.toBeChecked();
  await remember.check();
  await expect(remember).toBeChecked();
});

test('public shell never inherits the workspace sidebar offset on phones',async({page})=>{
  for(const width of [320,390,400,430]){
    await page.setViewportSize({width,height:900});
    for(const path of ['/','/product','/features']){
      await page.goto(path);
      const box=await page.evaluate(()=> {
        const main=document.querySelector('#main-content>main')?.getBoundingClientRect();
        const nav=document.querySelector('.publicNav')?.getBoundingClientRect();
        const brand=document.querySelector('.publicNav .publicBrand')?.getBoundingClientRect();
        const footer=document.querySelector('.publicFooter')?.getBoundingClientRect();
        return {
          mainLeft:main?.left??-1, mainRight:main?.right??-1,
          navLeft:nav?.left??-1, navRight:nav?.right??-1,
          brandLeft:brand?.left??-1,
          footerLeft:footer?.left??-1, footerRight:footer?.right??-1,
          client:document.documentElement.clientWidth,
          scroll:document.documentElement.scrollWidth
        };
      });
      expect(box.mainLeft).toBeGreaterThanOrEqual(-1);
      expect(box.mainLeft).toBeLessThanOrEqual(1);
      expect(Math.abs(box.mainRight-box.client)).toBeLessThanOrEqual(2);
      expect(box.navLeft).toBeGreaterThanOrEqual(-1);
      expect(box.navLeft).toBeLessThanOrEqual(1);
      expect(Math.abs(box.navRight-box.client)).toBeLessThanOrEqual(2);
      expect(box.brandLeft).toBeGreaterThanOrEqual(10);
      expect(box.brandLeft).toBeLessThanOrEqual(24);
      expect(box.footerLeft).toBeGreaterThanOrEqual(-1);
      expect(box.footerLeft).toBeLessThanOrEqual(1);
      expect(Math.abs(box.footerRight-box.client)).toBeLessThanOrEqual(2);
      expect(box.scroll).toBeLessThanOrEqual(box.client+2);
    }
  }
});

test('professional public design system keeps readable type cards and loaded real-world imagery',async({page})=>{
  for(const width of [390,768,1440]){
    await page.setViewportSize({width,height:1000});
    for(const path of ['/','/product','/developers','/enterprise']){
      await page.goto(path);
      const story=page.locator('.realWorldSection').first();
      await expect(story).toBeVisible();
      const image=story.locator('.realWorldMedia img');
      await expect(image).toBeVisible();
      await expect.poll(async()=>image.evaluate((el:any)=>el.complete&&el.naturalWidth>0)).toBe(true);
      const metrics=await page.evaluate(()=> {
        const sectionHeading=document.querySelector('.sectionHead h2') as HTMLElement|null;
        const storyHeading=document.querySelector('.realWorldCopy>h2') as HTMLElement|null;
        const cardHeading=document.querySelector('.featureCard h3,.homeModuleCard h3,.pageDetailGrid h2') as HTMLElement|null;
        const story=document.querySelector('.realWorldSection')?.getBoundingClientRect();
        return {
          sectionFont:sectionHeading?parseFloat(getComputedStyle(sectionHeading).fontSize):0,
          storyFont:storyHeading?parseFloat(getComputedStyle(storyHeading).fontSize):0,
          cardFont:cardHeading?parseFloat(getComputedStyle(cardHeading).fontSize):0,
          storyLeft:story?.left??-99,
          storyRight:story?.right??-99,
          client:document.documentElement.clientWidth,
          scroll:document.documentElement.scrollWidth
        };
      });
      expect(metrics.storyFont).toBeGreaterThanOrEqual(width<680?30:34);
      if(metrics.sectionFont) expect(metrics.sectionFont).toBeGreaterThanOrEqual(width<680?30:34);
      if(metrics.cardFont) expect(metrics.cardFont).toBeGreaterThanOrEqual(width<680?17:17);
      expect(metrics.storyLeft).toBeGreaterThanOrEqual(-1);
      expect(metrics.storyRight).toBeLessThanOrEqual(metrics.client+1);
      expect(metrics.scroll).toBeLessThanOrEqual(metrics.client+2);
    }
  }
});

test('authentication photography loads and form typography remains usable',async({page})=>{
  for(const width of [390,1024,1440]){
    await page.setViewportSize({width,height:1000});
    for(const path of ['/login','/signup']){
      await page.goto(path);
      const image=page.locator('.authPhotoBand img');
      await expect(image).toBeVisible();
      await expect.poll(async()=>image.evaluate((el:any)=>el.complete&&el.naturalWidth>0)).toBe(true);
      const metrics=await page.evaluate(()=> {
        const title=document.querySelector('.authCardExperience h1') as HTMLElement|null;
        const input=document.querySelector('.authCardExperience input') as HTMLElement|null;
        return {
          title:title?parseFloat(getComputedStyle(title).fontSize):0,
          input:input?parseFloat(getComputedStyle(input).fontSize):0,
          scroll:document.documentElement.scrollWidth,
          client:document.documentElement.clientWidth
        };
      });
      expect(metrics.title).toBeGreaterThanOrEqual(width<520?28:33);
      expect(metrics.input).toBeGreaterThanOrEqual(width<520?13:14);
      expect(metrics.scroll).toBeLessThanOrEqual(metrics.client+2);
    }
  }
});

