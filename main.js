// main.js
// فایل JavaScript اصلی برای سایت صفر اهم

// سیستم تطبیق هوشمند اندازه‌ها
function setupResponsiveScaling() {
    const container = document.querySelector('.main-container');
    const screenHeight = window.innerHeight;
    const screenWidth = window.innerWidth;
    
    // محاسبه فاکتور مقیاس بر اساس اندازه صفحه
    let scaleFactor = 1;
    
    if (screenHeight < 600) {
        scaleFactor = 0.9;
    } else if (screenHeight < 700) {
        scaleFactor = 0.95;
    } else if (screenHeight > 1000) {
        scaleFactor = 1.1;
    }
    
    if (screenWidth < 768) {
        scaleFactor *= 0.95;
    }
    
    // اعمال فاکتور مقیاس
    document.documentElement.style.setProperty('--scale-factor', scaleFactor);
    
    // تنظیم ارتفاع حداکثر برای لپ‌تاپ‌های مختلف
    let maxHeight = '90vh';
    if (screenHeight <= 768) {
        maxHeight = '95vh';
    } else if (screenHeight <= 600) {
        maxHeight = '98vh';
    }
    
    if (container) {
        container.style.maxHeight = maxHeight;
    }
    
    // تنظیمات خاص برای لپ‌تاپ
    const isLaptop = screenWidth >= 1024 && screenHeight <= 900;
    if (isLaptop) {
        document.body.style.padding = '15px';
        if (container) {
            container.style.borderRadius = '10px';
        }
    }
}

// سیستم مدیریت انیمیشن marquee
function setupMarqueeControl() {
    const infoBar = document.querySelector('.info-bar');
    const marquee = document.querySelector('.marquee');
    
    if (!infoBar || !marquee) return;
    
    // محاسبه سرعت بر اساس طول متن
    const textWidth = marquee.scrollWidth;
    const containerWidth = document.querySelector('.marquee-container').offsetWidth;
    
    // اگر متن کوتاه‌تر از عرض کانتینر است، نیازی به انیمیشن نیست
    if (textWidth <= containerWidth) {
        marquee.style.animation = 'none';
        return;
    }
    
    // محاسبه مدت زمان انیمیشن بر اساس طول متن
    const baseDuration = 25; // ثانیه برای متن استاندارد
    const duration = Math.max(baseDuration, (textWidth / containerWidth) * 20);
    
    // اعمال مدت زمان محاسبه شده
    marquee.style.animationDuration = `${duration}s`;
    
    // رفع مشکل توقف/شروع انیمیشن
    let isPaused = false;
    
    infoBar.addEventListener('mouseenter', function() {
        if (!isPaused) {
            marquee.style.animationPlayState = 'paused';
        }
    });
    
    infoBar.addEventListener('mouseleave', function() {
        if (!isPaused) {
            marquee.style.animationPlayState = 'running';
        }
    });
    
    // برای دستگاه‌های لمسی
    infoBar.addEventListener('touchstart', function() {
        if (!isPaused) {
            marquee.style.animationPlayState = 'paused';
            // بعد از 3 ثانیه خودکار ادام‌ه یابد
            setTimeout(() => {
                if (!isPaused) {
                    marquee.style.animationPlayState = 'running';
                }
            }, 3000);
        }
    });
    
    // کنترل مکث/شروع دستی
    marquee.addEventListener('click', function(e) {
        e.stopPropagation();
        isPaused = !isPaused;
        
        if (isPaused) {
            marquee.style.animationPlayState = 'paused';
            // نشانگر بصری برای حالت مکث
            marquee.style.opacity = '0.8';
        } else {
            marquee.style.animationPlayState = 'running';
            marquee.style.opacity = '1';
        }
    });
}

// تابع نمایش تب
function showTab(tabId) {
    console.log('Showing tab:', tabId); // برای دیباگ
    
    // مخفی کردن تمام تب‌ها
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => {
        tab.classList.remove('active');
    });
    
    // نمایش تب انتخاب شده
    const activeTab = document.getElementById(tabId + '-tab');
    if (activeTab) {
        activeTab.classList.add('active');
        console.log('Tab found and activated:', activeTab);
        
        // اسکرول به بالای محتوا
        const mainContent = document.querySelector('.main-content');
        if (mainContent) {
            mainContent.scrollTop = 0;
        }
    } else {
        console.error('Tab not found:', tabId + '-tab');
        // نمایش تب خانه به صورت پیش‌فرض
        document.getElementById('home-tab').classList.add('active');
    }
    
    return false;
}

// تابع انگلیسی
function showEnglish() {
    alert('English version is under development.\n\nFor English inquiries, please contact us at:\n📧 info@0hm.ir\n📞 +98 13 44266134');
    return false;
}

// تابع نمایش اینماد
function showEtrust() {
    // ایجاد یک مودال ساده برای نمایش تصویر بزرگ‌تر
    const modal = document.createElement('div');
    modal.style.position = 'fixed';
    modal.style.top = '0';
    modal.style.left = '0';
    modal.style.width = '100%';
    modal.style.height = '100%';
    modal.style.backgroundColor = 'rgba(0,0,0,0.7)';
    modal.style.display = 'flex';
    modal.style.justifyContent = 'center';
    modal.style.alignItems = 'center';
    modal.style.zIndex = '9999';
    
    const img = document.createElement('img');
    img.src = 'https://www.enamad.ir/Content/images/enamad-logo.png';
    img.style.maxWidth = '300px';
    img.style.maxHeight = '300px';
    img.style.backgroundColor = 'white';
    img.style.padding = '20px';
    img.style.borderRadius = '10px';
    img.style.boxShadow = '0 10px 30px rgba(0,0,0,0.3)';
    
    modal.appendChild(img);
    document.body.appendChild(modal);
    
    // بستن مودال با کلیک
    modal.onclick = function() {
        document.body.removeChild(modal);
    };
    
    return false;
}

// سیستم بهینه‌سازی کارت‌های محصول برای لپ‌تاپ
function optimizeProductCards() {
    const screenWidth = window.innerWidth;
    const productsGrid = document.querySelector('.products-grid');
    
    if (productsGrid) {
        if (screenWidth >= 1400) {
            // مانیتورهای بزرگ - 4 ستون
            productsGrid.style.gridTemplateColumns = 'repeat(4, 1fr)';
        } else if (screenWidth >= 1024) {
            // لپ‌تاپ - 2 ستون
            productsGrid.style.gridTemplateColumns = 'repeat(2, 1fr)';
        } else if (screenWidth >= 768) {
            // تبلت بزرگ - 2 ستون
            productsGrid.style.gridTemplateColumns = 'repeat(2, 1fr)';
        } else {
            // موبایل - 1 ستون
            productsGrid.style.gridTemplateColumns = '1fr';
        }
    }
}

// سیستم تشخیص و بهینه‌سازی برای لپ‌تاپ
function detectAndOptimizeForLaptop() {
    const screenHeight = window.innerHeight;
    const screenWidth = window.innerWidth;
    
    // تشخیص لپ‌تاپ بر اساس نسبت ابعاد
    const isLaptop = (screenWidth >= 1024 && screenWidth <= 1920) && 
                    (screenHeight >= 600 && screenHeight <= 1080) &&
                    (screenWidth > screenHeight);
    
    if (isLaptop) {
        // بهینه‌سازی‌های مخصوص لپ‌تاپ
        document.body.style.padding = '20px';
        document.body.style.overflow = 'hidden';
        
        const container = document.querySelector('.main-container');
        if (container) {
            container.style.width = 'min(1200px, 95%)';
            container.style.maxHeight = '90vh';
        }
        
        // تنظیم font-size برای خوانایی بهتر
        document.querySelectorAll('.home-text, .about-text, .contact-item-content').forEach(el => {
            el.style.fontSize = '14px';
            el.style.lineHeight = '1.7';
        });
        
        // تنظیم ارتفاع بنر
        const banner = document.querySelector('.banner');
        if (banner && screenHeight <= 768) {
            banner.style.height = '130px';
        }
    }
}

// پشتیبانی از مرورگرهای قدیمی
function checkMarqueeSupport() {
    const style = document.createElement('div').style;
    const properties = ['animation', 'WebkitAnimation', 'MozAnimation', 'OAnimation', 'msAnimation'];
    
    for (let prop of properties) {
        if (prop in style) {
            return true;
        }
    }
    
    // اگر انیمیشن CSS پشتیبانی نمی‌شود، از جاوااسکریپت استفاده کن
    return false;
}

// نسخه جایگزین با جاوااسکریپت برای مرورگرهای قدیمی
function setupJavaScriptMarquee() {
    const marqueeContainer = document.querySelector('.marquee-container');
    const marquee = document.querySelector('.marquee');
    
    if (!marqueeContainer || !marquee) return;
    
    // بررسی نیاز به انیمیشن
    const textWidth = marquee.scrollWidth;
    const containerWidth = marqueeContainer.offsetWidth;
    
    if (textWidth <= containerWidth) {
        marquee.style.paddingRight = '0';
        return;
    }
    
    let animationId;
    let position = 0;
    let isPaused = false;
    const speed = 0.5; // پیکسل در هر فریم
    
    function animate() {
        position -= speed;
        
        // اگر متن کاملاً از سمت چپ خارج شد، از راست دوباره شروع کن
        if (position <= -textWidth) {
            position = containerWidth;
        }
        
        marquee.style.transform = `translateX(${position}px)`;
        animationId = requestAnimationFrame(animate);
    }
    
    // کنترل با موس
    marqueeContainer.addEventListener('mouseenter', function() {
        if (!isPaused) {
            cancelAnimationFrame(animationId);
        }
    });
    
    marqueeContainer.addEventListener('mouseleave', function() {
        if (!isPaused) {
            animationId = requestAnimationFrame(animate);
        }
    });
    
    // کنترل کلیک
    marquee.addEventListener('click', function(e) {
        e.stopPropagation();
        isPaused = !isPaused;
        
        if (isPaused) {
            cancelAnimationFrame(animationId);
            marquee.style.opacity = '0.8';
        } else {
            animationId = requestAnimationFrame(animate);
            marquee.style.opacity = '1';
        }
    });
    
    // شروع انیمیشن
    animationId = requestAnimationFrame(animate);
}

// بهبود UX برای لپ‌تاپ
function optimizeUXForLaptop() {
    console.log('Page fully loaded');
    
    // افزودن hover effects بهتر برای لپ‌تاپ
    document.querySelectorAll('.product-card, .product-preview, .sidebar-item').forEach(el => {
        el.style.transition = 'all 0.3s ease';
    });
    
    // بهبود اسکرول برای لپ‌تاپ‌های تاچ‌اسکرین
    const mainContent = document.querySelector('.main-content');
    if (mainContent && 'ontouchstart' in window) {
        mainContent.style.overflowY = 'auto';
        mainContent.style.WebkitOverflowScrolling = 'touch';
    }
    
    // اطمینان از نمایش صحیح تب اول
    const activeTab = document.querySelector('.tab-content.active');
    if (!activeTab) {
        showTab('home');
    }
}

// تنظیم event listeners برای منوی ناوبری
function setupNavigationListeners() {
    document.querySelectorAll('.nav-item:not(:last-child):not(:nth-last-child(2))').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const text = this.textContent.trim();
            console.log('Nav clicked:', text);
            
            if (text === 'خانه') showTab('home');
            else if (text === 'محصولات') showTab('products');
            else if (text === 'درباره ما') showTab('about');
            else if (text === 'تماس') showTab('contact');
        });
    });
}

// تنظیم event listeners برای سایدبار
function setupSidebarListeners() {
    document.querySelectorAll('.sidebar-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            console.log('Sidebar clicked, showing products tab');
            showTab('products');
        });
    });
}

// تنظیم event listeners برای دکمه‌ها
function setupButtonListeners() {
    document.querySelectorAll('.btn-primary').forEach(btn => {
        if (btn.textContent.includes('مشاهده جزئیات')) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                showTab('products');
            });
        }
    });
}

// تنظیم کلیک روی تصویر اینماد
function setupEnamadClickListener() {
    const enamadImg = document.querySelector('.contact-box-enamad img');
    if (enamadImg) {
        enamadImg.addEventListener('click', function(e) {
            e.preventDefault();
            showEtrust();
        });
    }
}

// مقداردهی اولیه
function initialize() {
    console.log('DOM loaded, initializing...');
    
    setupResponsiveScaling();
    detectAndOptimizeForLaptop();
    optimizeProductCards();
    
    // بررسی پشتیبانی از انیمیشن CSS
    if (checkMarqueeSupport()) {
        setupMarqueeControl();
    } else {
        setupJavaScriptMarquee();
    }
    
    // نمایش تب خانه به صورت پیش‌فرض
    showTab('home');
    
    // تنظیم event listeners
    setupNavigationListeners();
    setupSidebarListeners();
    setupButtonListeners();
    setupEnamadClickListener();
    
    console.log('Initialization complete');
}

// رویداد تغییر اندازه پنجره
function handleResize() {
    setupResponsiveScaling();
    detectAndOptimizeForLaptop();
    optimizeProductCards();
    setupMarqueeControl();
}

// اکسپورت توابع برای استفاده در HTML
window.setupResponsiveScaling = setupResponsiveScaling;
window.showTab = showTab;
window.showEnglish = showEnglish;
window.showEtrust = showEtrust;
window.initialize = initialize;
window.handleResize = handleResize;
window.optimizeUXForLaptop = optimizeUXForLaptop;

// اجرای مقداردهی اولیه وقتی DOM آماده است
document.addEventListener('DOMContentLoaded', initialize);

// رویداد تغییر اندازه پنجره
window.addEventListener('resize', handleResize);

// رویداد لود کامل صفحه
window.addEventListener('load', optimizeUXForLaptop);