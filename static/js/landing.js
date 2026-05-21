/* landing.js - Hybrid Ink Cartography & Temporal Replay */

document.addEventListener('DOMContentLoaded', () => {
    
    // 1. Ceremonial Entrance
    const overlay = document.getElementById('entranceOverlay');
    const seal = document.getElementById('entranceSeal');
    const maskReveals = document.querySelectorAll('.mask-reveal'); 

    setTimeout(() => { if(seal) seal.style.opacity = '1'; }, 100);

    setTimeout(() => {
        if(overlay) overlay.style.opacity = '0';
        
        const heroReveals = document.querySelectorAll('header .mask-reveal');
        heroReveals.forEach(el => el.classList.add('in-view'));

        setTimeout(() => { if(overlay) overlay.remove(); }, 4000);
    }, 2000);

    // 2. Intersection Observer for Scroll Unfolding
    const observer = new IntersectionObserver((entries, obs) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('in-view');
                obs.unobserve(entry.target);
            }
        });
    }, { root: null, rootMargin: '0px', threshold: 0.1 });

    maskReveals.forEach(el => observer.observe(el));

    // 3. Archival Interaction: 3D Card Tilt
    const cards = document.querySelectorAll('.tilt-card');
    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const centerX = rect.width / 2;
            const centerY = rect.height / 2;
            const rotateX = ((y - centerY) / centerY) * -5;
            const rotateY = ((x - centerX) / centerX) * 5;
            card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.02, 1.02, 1.02)`;
        });
        card.addEventListener('mouseleave', () => {
            card.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)`;
        });
    });

    // 4. Ink-on-Parchment Background Network
    const bgCanvas = document.getElementById('deepNetworkCanvas');
    if (bgCanvas) initAstronomyNetwork(bgCanvas);

    // 5. Temporal Replay
    const temporalSection = document.getElementById('temporalReplaySection');
    const temporalCanvas = document.getElementById('temporalCanvas');
    const temporalYear = document.getElementById('temporalYear');
    if (temporalSection && temporalCanvas) {
        initTemporalReplay(temporalSection, temporalCanvas, temporalYear);
    }
});

/* --- CANVAS 1: INK ASTRONOMY NETWORK (Hero Section) --- */
function initAstronomyNetwork(canvas) {
    const ctx = canvas.getContext('2d');
    let width, height;
    let nodes = [];
    const nodeCount = 50;
    const maxDist = 200;
    let mouse = { x: -1000, y: -1000, radius: 250 };

    function resize() {
        width = canvas.clientWidth; height = canvas.clientHeight;
        canvas.width = width; canvas.height = height;
    }
    window.addEventListener('resize', resize); resize();
    window.addEventListener('mousemove', (e) => { mouse.x = e.x; mouse.y = e.y; });

    class AstroNode {
        constructor() {
            this.x = Math.random() * width; this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * 0.15; this.vy = (Math.random() - 0.5) * 0.15;
            this.r = Math.random() * 1.5 + 0.5;
        }
        update() {
            this.x += this.vx; this.y += this.vy;
            if (this.x < 0 || this.x > width) this.vx *= -1;
            if (this.y < 0 || this.y > height) this.vy *= -1;
            
            // Soft cursor gravity
            let dx = mouse.x - this.x; let dy = mouse.y - this.y;
            let dist = Math.sqrt(dx*dx + dy*dy);
            if(dist < mouse.radius) {
                this.x += dx * 0.002; this.y += dy * 0.002;
            }
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(44, 44, 44, 0.3)`; // Dark ink node
            ctx.fill();
        }
    }

    for(let i=0; i<nodeCount; i++) nodes.push(new AstroNode());

    function draw() {
        ctx.clearRect(0, 0, width, height);
        for(let i=0; i<nodes.length; i++) {
            nodes[i].update();
            nodes[i].draw();
            for(let j=i+1; j<nodes.length; j++) {
                let dx = nodes[i].x - nodes[j].x; let dy = nodes[i].y - nodes[j].y;
                let dist = Math.sqrt(dx*dx + dy*dy);
                if(dist < maxDist) {
                    let op = (1 - dist/maxDist) * 0.15;
                    
                    let mDist = Math.sqrt(Math.pow(mouse.x - nodes[i].x, 2) + Math.pow(mouse.y - nodes[i].y, 2));
                    if(mDist < mouse.radius) op *= 2.5;

                    ctx.beginPath();
                    ctx.moveTo(nodes[i].x, nodes[i].y);
                    let cx = (nodes[i].x + nodes[j].x)/2 + (nodes[i].y - nodes[j].y)*0.1;
                    let cy = (nodes[i].y + nodes[j].y)/2 + (nodes[j].x - nodes[i].x)*0.1;
                    ctx.quadraticCurveTo(cx, cy, nodes[j].x, nodes[j].y);
                    
                    // Dark tea-brown / ink connection
                    ctx.strokeStyle = `rgba(140, 122, 107, ${op})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
        if(!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            requestAnimationFrame(draw);
        }
    }
    draw();
}

/* --- CANVAS 2: TEMPORAL REPLAY (Ink Scrubbing) --- */
function initTemporalReplay(section, canvas, yearEl) {
    const ctx = canvas.getContext('2d');
    let width, height;
    function resize() {
        width = canvas.clientWidth; height = canvas.clientHeight;
        canvas.width = width; canvas.height = height;
    }
    window.addEventListener('resize', resize); resize();

    // Pre-generate historical sweeps
    const sweeps = [];
    for(let s=0; s<5; s++) {
        let nodes = [];
        for(let i=0; i<40; i++) {
            nodes.push({x: Math.random(), y: Math.random()}); 
        }
        sweeps.push(nodes);
    }

    function drawSweep(sweepIndex, alpha, isCurrent) {
        let nodes = sweeps[sweepIndex];
        
        if (isCurrent) {
            ctx.strokeStyle = `rgba(44, 44, 44, ${alpha})`; // Deep Ink
            ctx.fillStyle = `rgba(139, 38, 38, ${alpha})`; // Seal Red nodes for current
            ctx.lineWidth = 1.5;
        } else {
            ctx.strokeStyle = `rgba(140, 122, 107, ${alpha})`; // Tea brown ghost
            ctx.fillStyle = `rgba(140, 122, 107, ${alpha * 1.5})`; 
            ctx.lineWidth = 0.5;
        }
        
        nodes.forEach((n, i) => {
            let px = n.x * width; let py = n.y * height;
            ctx.beginPath(); ctx.arc(px, py, isCurrent ? 3 : 2, 0, Math.PI*2); ctx.fill();
            for(let j=i+1; j<Math.min(i+4, nodes.length); j++) {
                let px2 = nodes[j].x * width; let py2 = nodes[j].y * height;
                ctx.beginPath(); ctx.moveTo(px, py); ctx.lineTo(px2, py2); ctx.stroke();
            }
        });
    }

    // Scroll listener just for this section
    window.addEventListener('scroll', () => {
        const rect = section.getBoundingClientRect();
        if(rect.top < window.innerHeight && rect.bottom > 0) {
            let progress = Math.max(0, Math.min(1, -rect.top / (rect.height - window.innerHeight)));
            
            ctx.clearRect(0, 0, width, height);
            
            let sweepCount = sweeps.length;
            let currentSweepFloat = progress * (sweepCount - 1);
            let currentSweep = Math.floor(currentSweepFloat);
            
            yearEl.innerText = `T-${(sweepCount - 1 - currentSweep)}`;

            // Draw past ghosts
            for(let i=0; i<=currentSweep; i++) {
                let fade = 1 - (currentSweepFloat - i) * 0.5;
                if(fade > 0) {
                    drawSweep(i, fade * 0.15, false);
                }
            }

            // Draw current active sweep
            let activeAlpha = (currentSweepFloat - currentSweep); 
            drawSweep(Math.min(currentSweep + 1, sweepCount - 1), activeAlpha * 0.6, true);
        }
    }, { passive: true });
}
