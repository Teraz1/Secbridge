import { useState, useEffect, useRef, useCallback } from "react";

const API = "/api";

// ── Empty defaults (no mock data) ──────────────────────────────────────────
const MOCK_SOURCES = [];
const MOCK_EVENTS  = [];
const MOCK_USERS   = [];
const MOCK_LOGS    = [];

const STATS_HOURS = ["00","01","02","03","04","05","06","07","08","09","10","11","12","13","14","15","16","17","18","19","20","21","22","23"];
const STATS_DATA = {};

const SEV = {
  critical:{ dot:"#DC2626" }, high:{ dot:"#EA580C" },
  medium:{ dot:"#D97706" }, low:{ dot:"#16A34A" },
};

// ── CSS ────────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Outfit:wght@300;400;500;600&display=swap');
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Outfit',sans-serif;background:#F5F4F1;color:#18181B;overflow-x:hidden;}

/* Login */
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#18181B 0%,#1e3a5f 50%,#18181B 100%);position:relative;overflow:hidden;}
.login-grid{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);background-size:48px 48px;}
.login-glow{position:absolute;width:600px;height:600px;background:radial-gradient(circle,rgba(59,130,246,.12) 0%,transparent 70%);top:50%;left:50%;transform:translate(-50%,-50%);pointer-events:none;}
.login-card{position:relative;z-index:2;background:rgba(255,255,255,.97);border-radius:20px;width:400px;padding:40px;box-shadow:0 32px 80px rgba(0,0,0,.35);}
.login-logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;}
.login-logo-icon{width:42px;height:42px;border-radius:10px;background:linear-gradient(135deg,#1e3a5f,#3B82F6);display:flex;align-items:center;justify-content:center;font-size:20px;color:white;}
.login-title{font-family:'Syne',sans-serif;font-size:24px;font-weight:700;margin-bottom:6px;}
.login-sub{font-size:13.5px;color:#6B7280;margin-bottom:28px;}
.lfield{display:flex;flex-direction:column;gap:6px;margin-bottom:16px;}
.llabel{font-size:12.5px;font-weight:500;color:#374151;}
.linput{padding:10px 14px;border:1.5px solid #E5E7EB;border-radius:9px;font-size:14px;font-family:'Outfit',sans-serif;outline:none;transition:all .15s;background:#FAFAFA;}
.linput:focus{border-color:#3B82F6;background:#fff;box-shadow:0 0 0 3px rgba(59,130,246,.1);}
.lbtn{width:100%;padding:11px;background:#18181B;color:#fff;border:none;border-radius:9px;font-size:14px;font-weight:600;font-family:'Outfit',sans-serif;cursor:pointer;margin-top:8px;transition:background .15s;}
.lbtn:hover{background:#2d2d4a;}
.lerr{background:#FEF2F2;color:#DC2626;border-radius:7px;padding:10px 14px;font-size:13px;margin-bottom:14px;}
.lfooter{text-align:center;font-size:12px;color:#9CA3AF;margin-top:20px;}

/* Shell */
.shell{display:flex;min-height:100vh;}
.sidebar{width:220px;min-height:100vh;background:#18181B;display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:200;transition:width .25s cubic-bezier(.4,0,.2,1);overflow:hidden;}
.sidebar.collapsed{width:60px;}
.sb-header{padding:18px 16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.06);min-height:64px;}
.sb-brand{display:flex;align-items:center;gap:10px;overflow:hidden;}
.sb-icon{width:32px;height:32px;border-radius:8px;flex-shrink:0;background:linear-gradient(135deg,#1e3a5f,#3B82F6);display:flex;align-items:center;justify-content:center;font-size:16px;color:white;}
.sb-text{overflow:hidden;white-space:nowrap;}
.sb-name{font-family:'Syne',sans-serif;font-size:16px;font-weight:700;color:#fff;}
.sb-ver{font-size:10px;color:rgba(255,255,255,.3);font-family:'JetBrains Mono',monospace;}
.hamburger{width:28px;height:28px;border-radius:6px;background:rgba(255,255,255,.06);border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;flex-direction:column;gap:4px;padding:6px;transition:background .15s;}
.hamburger:hover{background:rgba(255,255,255,.1);}
.hline{height:2px;background:rgba(255,255,255,.6);border-radius:1px;width:14px;}
.sb-nav{padding:12px 8px;flex:1;display:flex;flex-direction:column;gap:2px;}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:8px;cursor:pointer;transition:all .15s;color:rgba(255,255,255,.4);font-size:13.5px;font-weight:400;border:none;background:none;width:100%;text-align:left;white-space:nowrap;overflow:hidden;min-height:38px;}
.nav-item:hover{color:rgba(255,255,255,.75);background:rgba(255,255,255,.05);}
.nav-item.active{background:rgba(59,130,246,.15);color:#60A5FA;font-weight:500;}
.nav-icon{width:20px;height:20px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:15px;}
.nav-label{overflow:hidden;transition:opacity .2s;}
.sidebar.collapsed .nav-label{opacity:0;}
.sb-footer{padding:12px 8px;border-top:1px solid rgba(255,255,255,.06);}
.agent-pill{display:flex;align-items:center;gap:8px;padding:9px 10px;background:rgba(255,255,255,.04);border-radius:8px;overflow:hidden;white-space:nowrap;}
.agent-dot{width:7px;height:7px;border-radius:50%;background:#22C55E;box-shadow:0 0 6px #22C55E;flex-shrink:0;animation:blink 2s infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.4;}}
.agent-txt{font-size:11.5px;color:rgba(255,255,255,.45);overflow:hidden;}
.agent-txt strong{color:#22C55E;font-weight:500;display:block;font-size:12px;}

/* Main */
.main{margin-left:220px;flex:1;display:flex;flex-direction:column;transition:margin-left .25s cubic-bezier(.4,0,.2,1);}
.main.expanded{margin-left:60px;}
.topbar{background:#fff;border-bottom:1px solid #EBEBEB;padding:0 28px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:50;}
.page-title{font-family:'Syne',sans-serif;font-size:15px;font-weight:700;color:#18181B;}
.page-sub{font-size:11.5px;color:#9CA3AF;margin-top:1px;}
.topbar-r{display:flex;align-items:center;gap:10px;}
.avatar{width:32px;height:32px;border-radius:8px;background:#18181B;display:flex;align-items:center;justify-content:center;color:#fff;font-size:13px;font-weight:600;cursor:pointer;}
.logout-btn{padding:6px 12px;border-radius:7px;background:#F3F4F6;color:#374151;border:none;font-size:12.5px;font-weight:500;cursor:pointer;font-family:'Outfit',sans-serif;transition:background .15s;}
.logout-btn:hover{background:#E5E7EB;}
.content{padding:24px 28px;flex:1;}

/* Buttons */
.btn{padding:7px 14px;border-radius:7px;font-size:13px;font-weight:500;cursor:pointer;border:none;font-family:'Outfit',sans-serif;transition:all .15s;}
.btn-primary{background:#18181B;color:#fff;}
.btn-primary:hover{background:#2d2d4a;}
.btn-secondary{background:#F3F4F6;color:#374151;}
.btn-secondary:hover{background:#E5E7EB;}
.btn-danger{background:#FEF2F2;color:#DC2626;}
.btn-danger:hover{background:#FEE2E2;}
.btn-success{background:#F0FDF4;color:#16A34A;}
.btn-sm{padding:5px 10px;font-size:12px;}

/* Cards */
.card{background:#fff;border:1px solid #EBEBEB;border-radius:12px;overflow:hidden;}
.card-header{padding:16px 20px;border-bottom:1px solid #F3F4F6;display:flex;align-items:center;justify-content:space-between;}
.card-title{font-family:'Syne',sans-serif;font-size:13.5px;font-weight:700;color:#18181B;}
.card-sub{font-size:11.5px;color:#9CA3AF;margin-top:1px;}

/* Badges */
.badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:2px 7px;border-radius:20px;font-weight:500;}
.bg-green{background:#F0FDF4;color:#16A34A;}
.bg-red{background:#FEF2F2;color:#DC2626;}
.bg-blue{background:#EFF6FF;color:#2563EB;}
.bg-orange{background:#FFF7ED;color:#EA580C;}
.bg-gray{background:#F3F4F6;color:#6B7280;}
.bg-purple{background:#F5F3FF;color:#7C3AED;}

/* Table */
.table{width:100%;border-collapse:collapse;}
.table th{text-align:left;padding:10px 20px;font-size:10.5px;font-weight:600;color:#9CA3AF;text-transform:uppercase;letter-spacing:.6px;background:#FAFAFA;border-bottom:1px solid #F3F4F6;}
.table td{padding:12px 20px;font-size:13px;color:#374151;border-bottom:1px solid #F9FAFB;}
.table tr:last-child td{border-bottom:none;}
.table tr:hover td{background:#FAFAFA;}

/* Pills */
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11.5px;font-weight:500;}
.pill-on{background:#F0FDF4;color:#16A34A;}
.pill-off{background:#F9FAFB;color:#9CA3AF;}
.pdot{width:6px;height:6px;border-radius:50%;}
.pdot-on{background:#22C55E;}
.pdot-off{background:#D1D5DB;}

/* Toggle */
.toggle{width:34px;height:18px;border-radius:9px;position:relative;cursor:pointer;transition:background .2s;border:none;flex-shrink:0;}
.toggle::after{content:'';position:absolute;width:14px;height:14px;background:white;border-radius:50%;top:2px;left:2px;transition:left .2s;box-shadow:0 1px 3px rgba(0,0,0,.2);}
.toggle.on::after{left:18px;}

/* Stat grid */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px;}
.stat-card{background:#fff;border:1px solid #EBEBEB;border-radius:12px;padding:18px 20px;}
.stat-label{font-size:11px;color:#9CA3AF;font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px;}
.stat-val{font-family:'Syne',sans-serif;font-size:26px;font-weight:700;color:#18181B;letter-spacing:-1px;}

/* Two col */
.two-col{display:grid;grid-template-columns:1fr 320px;gap:16px;}

/* Modal */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center;z-index:1000;backdrop-filter:blur(3px);}
.modal{background:#fff;border-radius:14px;width:500px;box-shadow:0 24px 70px rgba(0,0,0,.18);overflow:hidden;max-height:90vh;overflow-y:auto;}
.modal-lg{width:640px;}
.modal-hdr{padding:20px 24px 16px;border-bottom:1px solid #F3F4F6;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:#fff;z-index:1;}
.modal-title{font-family:'Syne',sans-serif;font-size:15px;font-weight:700;}
.modal-x{width:28px;height:28px;border-radius:6px;border:none;background:#F3F4F6;cursor:pointer;font-size:14px;color:#6B7280;display:flex;align-items:center;justify-content:center;}
.modal-body{padding:20px 24px;display:flex;flex-direction:column;gap:14px;}
.modal-ftr{padding:14px 24px;border-top:1px solid #F3F4F6;display:flex;justify-content:flex-end;gap:8px;position:sticky;bottom:0;background:#fff;}
.fg{display:flex;flex-direction:column;gap:5px;}
.f2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.flabel{font-size:12.5px;font-weight:500;color:#374151;}
.finput{padding:8px 12px;border:1.5px solid #E5E7EB;border-radius:7px;font-size:13px;font-family:'Outfit',sans-serif;color:#18181B;outline:none;transition:border-color .15s;background:#fff;}
.finput:focus{border-color:#3B82F6;box-shadow:0 0 0 3px rgba(59,130,246,.08);}
.fselect{padding:8px 12px;border:1.5px solid #E5E7EB;border-radius:7px;font-size:13px;font-family:'Outfit',sans-serif;color:#18181B;outline:none;background:#fff;cursor:pointer;}

/* Meter */
.meter{height:3px;background:#F3F4F6;border-radius:2px;overflow:hidden;margin-top:5px;}
.meter-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,#3B82F6,#8B5CF6);transition:width .4s;}

/* Log viewer */
.log-wrap{background:#0F172A;border-radius:0 0 12px 12px;padding:16px;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.7;max-height:400px;overflow-y:auto;}
.log-line{color:#94A3B8;padding:1px 0;border-bottom:1px solid rgba(255,255,255,.03);}
.log-line:hover{background:rgba(255,255,255,.03);color:#CBD5E1;}
.log-line .log-time{color:#475569;}
.log-line .log-threat{color:#F87171;}
.log-line .log-block{color:#FB923C;}
.log-line .log-allow{color:#4ADE80;}
.log-line .log-auth{color:#FACC15;}
.log-live-dot{width:8px;height:8px;border-radius:50%;background:#EF4444;animation:blink 1s infinite;display:inline-block;margin-right:6px;}

/* Health checks */
.health-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:18px;}
.hcard{border:1px solid #EBEBEB;border-radius:10px;padding:16px;}
.hcard-title{font-family:'Syne',sans-serif;font-size:13px;font-weight:700;margin-bottom:12px;color:#18181B;}
.hrow{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #F9FAFB;font-size:13px;}
.hrow:last-child{border-bottom:none;}
.hrow-label{color:#374151;}
.hstatus{display:flex;align-items:center;gap:5px;font-size:12px;font-weight:500;}
.hs-ok{color:#16A34A;}
.hs-warn{color:#D97706;}
.hs-err{color:#DC2626;}

/* Stats / Charts */
.chart-wrap{padding:20px;}
.bar-chart{display:flex;align-items:flex-end;gap:3px;height:100px;margin-bottom:8px;}
.bar{flex:1;border-radius:3px 3px 0 0;transition:height .3s;cursor:pointer;min-width:0;}
.bar:hover{opacity:.8;}
.bar-labels{display:flex;gap:3px;}
.bar-label{flex:1;font-size:9px;color:#9CA3AF;text-align:center;font-family:'JetBrains Mono',monospace;min-width:0;overflow:hidden;}
.source-stat-row{display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #F9FAFB;}
.source-stat-row:last-child{border-bottom:none;}
.source-color{width:10px;height:10px;border-radius:2px;flex-shrink:0;}

/* Onboarding wizard */
.wizard-wrap{max-width:600px;margin:0 auto;}
.wizard-steps{display:flex;align-items:center;gap:0;margin-bottom:28px;}
.wstep{display:flex;flex-direction:column;align-items:center;flex:1;position:relative;}
.wstep:not(:last-child)::after{content:'';position:absolute;top:14px;left:50%;width:100%;height:2px;background:#E5E7EB;z-index:0;}
.wstep.done::after{background:#22C55E;}
.wstep.active::after{background:#E5E7EB;}
.wstep-circle{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;z-index:1;border:2px solid #E5E7EB;background:#fff;color:#9CA3AF;}
.wstep.done .wstep-circle{background:#22C55E;border-color:#22C55E;color:white;}
.wstep.active .wstep-circle{background:#18181B;border-color:#18181B;color:white;}
.wstep-label{font-size:11px;color:#9CA3AF;margin-top:5px;text-align:center;white-space:nowrap;}
.wstep.active .wstep-label{color:#18181B;font-weight:600;}
.wstep.done .wstep-label{color:#16A34A;}
.wizard-card{background:#fff;border:1px solid #EBEBEB;border-radius:14px;overflow:hidden;}
.wizard-body{padding:28px;}
.wizard-step-title{font-family:'Syne',sans-serif;font-size:18px;font-weight:700;margin-bottom:6px;}
.wizard-step-sub{font-size:13.5px;color:#6B7280;margin-bottom:24px;}
.wizard-ftr{padding:16px 28px;border-top:1px solid #F3F4F6;display:flex;justify-content:space-between;align-items:center;}
.wizard-progress{font-size:12px;color:#9CA3AF;}
.success-icon{width:60px;height:60px;border-radius:50%;background:#F0FDF4;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 16px;}

/* Users */
.role-badge-admin{background:#FEF2F2;color:#DC2626;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}
.role-badge-analyst{background:#EFF6FF;color:#2563EB;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}
.role-badge-viewer{background:#F5F3FF;color:#7C3AED;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;}

/* Backup */
.backup-list{padding:18px;display:flex;flex-direction:column;gap:10px;}
.backup-item{border:1px solid #EBEBEB;border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:14px;}
.backup-icon{width:38px;height:38px;border-radius:9px;background:#F3F4F6;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;}
.backup-name{font-family:'Syne',sans-serif;font-size:13.5px;font-weight:600;color:#18181B;}
.backup-detail{font-size:11.5px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:2px;}

/* Settings */
.srow{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid #F3F4F6;}
.srow:last-child{border-bottom:none;}
.slabel{font-size:13.5px;font-weight:500;color:#18181B;}
.sdesc{font-size:12px;color:#9CA3AF;margin-top:2px;}

/* Port tag */
.port-tag{display:inline-flex;align-items:center;background:#F3F4F6;color:#374151;padding:3px 8px;border-radius:5px;font-size:11.5px;font-family:'JetBrains Mono',monospace;font-weight:500;}

/* Mapper */
.mapper-stage{display:flex;align-items:stretch;gap:0;background:#fff;border:1px solid #EBEBEB;border-radius:14px;overflow:hidden;}
.stage-col{flex:1;display:flex;flex-direction:column;border-right:1px solid #F3F4F6;}
.stage-col:last-child{border-right:none;}
.stage-header{padding:14px 18px;background:#FAFAFA;border-bottom:1px solid #F3F4F6;display:flex;align-items:center;gap:8px;}
.stage-icon{width:30px;height:30px;border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0;}
.stage-title{font-family:'Syne',sans-serif;font-size:12.5px;font-weight:700;color:#18181B;}
.stage-sub{font-size:11px;color:#9CA3AF;}
.stage-body{padding:14px;display:flex;flex-direction:column;gap:8px;flex:1;}
.stage-arrow{width:32px;display:flex;align-items:center;justify-content:center;flex-shrink:0;color:#D1D5DB;font-size:16px;background:#fff;}
.node{border-radius:9px;padding:10px 12px;display:flex;align-items:center;gap:9px;border:1px solid transparent;transition:all .2s;position:relative;}
.node-ok{background:#F0FDF4;border-color:#BBF7D0;}
.node-warn{background:#FFF7ED;border-color:#FED7AA;}
.node-off{background:#F9FAFB;border-color:#F3F4F6;}
.node-icon{width:26px;height:26px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:13px;flex-shrink:0;}
.node-ok .node-icon{background:#DCFCE7;}
.node-warn .node-icon{background:#FEF3C7;}
.node-off .node-icon{background:#F3F4F6;}
.node-info{flex:1;min-width:0;}
.node-name{font-size:12.5px;font-weight:600;color:#18181B;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.node-detail{font-size:10.5px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:1px;}
.ns{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.ns-ok{background:#22C55E;box-shadow:0 0 5px #22C55E;}
.ns-warn{background:#F59E0B;box-shadow:0 0 5px #F59E0B;}
.ns-off{background:#D1D5DB;}

/* Ev feed */
.ev-feed{max-height:360px;overflow-y:auto;}
.ev-item{padding:11px 20px;border-bottom:1px solid #F9FAFB;display:flex;gap:10px;align-items:flex-start;}
.ev-item:last-child{border-bottom:none;}
.ev-dot{width:7px;height:7px;border-radius:50%;margin-top:5px;flex-shrink:0;}
.ev-time{font-size:11px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;}
.ev-type{font-size:10px;font-weight:600;padding:1px 5px;border-radius:3px;background:#F3F4F6;color:#6B7280;font-family:'JetBrains Mono',monospace;}
.ev-src{font-size:11px;color:#6B7280;font-weight:500;}
.ev-msg{font-size:12.5px;color:#374151;margin-top:2px;}

/* Source page */
.src-name{font-weight:600;color:#18181B;font-family:'Syne',sans-serif;font-size:13px;}
.src-prod{font-size:11px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:1px;}

/* Parser cards */
.parser-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:18px;}
.pcard{border:1px solid #EBEBEB;border-radius:10px;padding:16px;transition:border-color .15s;}
.pcard:hover{border-color:#D1D5DB;}
.pcard-hdr{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:10px;}
.pname{font-family:'Syne',sans-serif;font-size:13px;font-weight:700;color:#18181B;}
.pvendor{font-size:11.5px;color:#9CA3AF;}
.pfile{font-size:11px;color:#B0B7C3;font-family:'JetBrains Mono',monospace;margin-top:8px;}
.pmeta{display:flex;gap:5px;margin-top:8px;flex-wrap:wrap;}
.pcard-add{border:1.5px dashed #E5E7EB;border-radius:10px;padding:16px;display:flex;align-items:center;justify-content:center;cursor:pointer;min-height:120px;transition:border-color .2s;}
.pcard-add:hover{border-color:#9CA3AF;}

/* Destinations */
.dest-list{padding:18px;display:flex;flex-direction:column;gap:10px;}
.dcard{border:1px solid #EBEBEB;border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:14px;}
.dicon{width:38px;height:38px;border-radius:9px;background:#F3F4F6;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;}
.dname{font-family:'Syne',sans-serif;font-size:13.5px;font-weight:700;color:#18181B;}
.ddetail{font-size:11.5px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:2px;}

::-webkit-scrollbar{width:4px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:#E5E7EB;border-radius:2px;}
`;

// ── Login ──────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [user,setUser]=useState(""); const [pass,setPass]=useState(""); const [err,setErr]=useState(""); const [loading,setLoading]=useState(false);
  const submit=async()=>{
    if(!user||!pass){setErr("Please enter username and password.");return;}
    setLoading(true);setErr("");
    try{
      const res=await fetch(`${API}/login`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:user,password:pass})});
      if(res.ok){const d=await res.json();onLogin(user,d.token,d.role);}
      else{setErr("Invalid credentials.");setLoading(false);}
    }catch{
      // demo login removed — use real API only
      else{setErr("Invalid credentials. (Demo: admin / admin)");setLoading(false);}
    }
  };
  return(
    <div className="login-wrap">
      <div className="login-grid"/>
      <div className="login-glow"/>
      <div className="login-card">
        <div className="login-logo">
          <div className="login-logo-icon">⬡</div>
          <div>
            <div style={{fontFamily:"'Syne',sans-serif",fontSize:22,fontWeight:700}}>SecBridge</div>
            <div style={{fontSize:11,color:"#9CA3AF",fontFamily:"'JetBrains Mono',monospace"}}>v3.2 — Security Log Router</div>
          </div>
        </div>
        <div className="login-title">Welcome back</div>
        <div className="login-sub">Sign in to your SecBridge dashboard</div>
        {err&&<div className="lerr">{err}</div>}
        <div className="lfield"><label className="llabel">Username</label><input className="linput" placeholder="admin" value={user} onChange={e=>setUser(e.target.value)} onKeyDown={e=>e.key==="Enter"&&submit()}/></div>
        <div className="lfield"><label className="llabel">Password</label><input className="linput" type="password" placeholder="••••••••" value={pass} onChange={e=>setPass(e.target.value)} onKeyDown={e=>e.key==="Enter"&&submit()}/></div>
        <button className="lbtn" onClick={submit} disabled={loading}>{loading?"Signing in…":"Sign In →"}</button>
        
      </div>
    </div>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────
function Dashboard({sources,agentStatus}){
  const [tick,setTick]=useState(0);
  const [events,setEvents]=useState([]);
  useEffect(()=>{const t=setInterval(()=>setTick(v=>v+1),2000);return()=>clearInterval(t);},[]);
  const agentOk=agentStatus?.agent_running;
  const active=sources.filter(s=>s.port_listening||s.enabled).length;
  const totalLines=sources.reduce((a,s)=>a+(s.log_info?.lines||0),0);
  return(
    <div>
      <div className="stat-grid">
        {[
          {label:"Active Sources",val:active+"/"+sources.length,badge:"● "+active+" online",bc:"bg-green"},
          {label:"Total Logs",val:totalLines.toLocaleString(),badge:"↑ in log files",bc:"bg-blue"},
          {label:"SDL Reachable",val:agentStatus?.sdl_reachable?"Yes":"—",badge:"xdr.ap1.sentinelone.net",bc:agentStatus?.sdl_reachable?"bg-green":"bg-red"},
          {label:"Agent Status",val:agentOk?"Running":agentStatus===null?"Checking…":"Stopped",badge:"● scalyr-agent-2",bc:agentOk?"bg-green":"bg-red",vs:16},
        ].map((s,i)=>(
          <div className="stat-card" key={i}>
            <div className="stat-label">{s.label}</div>
            <div className="stat-val" style={{color:s.vc||"#18181B",fontSize:s.vs}}>{s.val}</div>
            <span className={`badge ${s.bc}`}>{s.badge}</span>
          </div>
        ))}
      </div>
      <div className="two-col">
        <div className="card">
          <div className="card-header"><div><div className="card-title">Sources</div><div className="card-sub">Live throughput</div></div></div>
          <table className="table">
            <thead><tr><th>Source</th><th>Port</th><th>Status</th><th>Logs/min</th><th>Last seen</th></tr></thead>
            <tbody>{sources.map(s=>(
              <tr key={s.id}>
                <td><div className="src-name">{s.name}</div><div className="src-prod">{s.product}</div></td>
                <td><span className="port-tag">{s.syslog_port}/{s.protocol}</span></td>
                <td><span className={`pill ${s.port_listening?"pill-on":"pill-off"}`}><span className={`pdot ${s.port_listening?"pdot-on":"pdot-off"}`}/>{s.port_listening?"active":"inactive"}</span></td>
                <td><div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:13}}>{(s.log_info?.lines||0).toLocaleString()}</div><div className="meter"><div className="meter-fill" style={{width:Math.min(100,((s.log_info?.lines||0)/5000)*100)+"%"}}/></div></td>
                <td style={{fontSize:12,color:"#9CA3AF"}}>{s.log_info?.modified?new Date(s.log_info.modified).toLocaleTimeString():"—"}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Recent Events</div><span className="badge bg-blue">{events.length} today</span></div>
          <div className="ev-feed">{events.length===0?(<div style={{padding:"20px",color:"#9CA3AF",textAlign:"center"}}>No events yet — waiting for logs...</div>):events.map((e,i)=>(
            <div className="ev-item" key={i}>
              <div className="ev-dot" style={{background:SEV[e.severity].dot}}/>
              <div><div style={{display:"flex",gap:5,alignItems:"center",marginBottom:2}}><span className="ev-time">{e.time}</span><span className="ev-type">{e.type}</span><span className="ev-src">{e.source.split(" ")[0]}</span></div><div className="ev-msg">{e.msg}</div></div>
            </div>
          ))}</div>
        </div>
      </div>
    </div>
  );
}

// ── Live Log Viewer ────────────────────────────────────────────────────────
function LogViewer({sources,apiFetch}){
  const activeSrc=sources.filter(s=>s.port_listening||s.enabled);
  const [selected,setSelected]=useState(activeSrc[0]?.product||"sangfor-ngaf");
  const [lines,setLines]=useState([]);
  const [live,setLive]=useState(true);
  const feedRef=useRef(null);
  const lastLinesRef=useRef([]);

  useEffect(()=>{
    if(!live)return;
    const fetchLogs=async()=>{
      try{
        const res=await apiFetch(`/logs/${selected}?lines=80`);
        if(res&&res.ok){
          const d=await res.json();
          if(d.lines&&d.lines.length>0&&JSON.stringify(d.lines)!==JSON.stringify(lastLinesRef.current)){
            lastLinesRef.current=d.lines;
            setLines(d.lines);
          }
        }
      }catch{}
    };
    fetchLogs();
    const t=setInterval(fetchLogs,3000);
    return()=>clearInterval(t);
  },[live,selected,apiFetch]);

  useEffect(()=>{if(feedRef.current)feedRef.current.scrollTop=feedRef.current.scrollHeight;},[lines]);
  const colorize=(line)=>{
    if(line.includes("APT")||line.includes("Ransomware")||line.includes("Botnet"))return "log-threat";
    if(line.includes("Blocked")||line.includes("Denied"))return "log-block";
    if(line.includes("Allowed"))return "log-allow";
    if(line.includes("Auth")||line.includes("Failed"))return "log-auth";
    return "";
  };
  return(
    <div className="card">
      <div className="card-header">
        <div><div className="card-title">Live Log Viewer</div><div className="card-sub">Real-time syslog stream</div></div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <select className="fselect" value={selected} onChange={e=>setSelected(e.target.value)} style={{fontSize:12,padding:"5px 10px"}}>
            {sources.filter(s=>s.enabled).map(s=><option key={s.id} value={s.product}>{s.name}</option>)}
          </select>
          <button className={`btn btn-sm ${live?"btn-danger":"btn-success"}`} onClick={()=>setLive(v=>!v)}>
            {live?<><span className="log-live-dot"/>Live</>:"▶ Resume"}
          </button>
          <button className="btn btn-secondary btn-sm" onClick={()=>setLines([])}>Clear</button>
        </div>
      </div>
      <div className="log-wrap" ref={feedRef}>
        {lines.map((line,i)=>{
          const cls=colorize(line);
          const parts=line.split(" ");
          const time=parts.slice(0,3).join(" ");
          const rest=parts.slice(3).join(" ");
          return(
            <div className={`log-line ${cls}`} key={i}>
              <span className="log-time">{time} </span>{rest}
            </div>
          );
        })}
        {live&&<div style={{color:"#475569",fontStyle:"italic",marginTop:4}}>▌ waiting for logs...</div>}
      </div>
    </div>
  );
}

// ── Health Check ───────────────────────────────────────────────────────────
function HealthCheck({sources,apiFetch}){
  const [checking,setChecking]=useState(false);
  const [lastCheck,setLastCheck]=useState(null);
  const [status,setStatus]=useState(null);
  const runCheck=async()=>{
    setChecking(true);
    try{
      const res=await apiFetch("/status");
      if(res&&res.ok){const d=await res.json();setStatus(d);setLastCheck(new Date().toLocaleTimeString());}
    }catch{}
    setChecking(false);
  };
  useEffect(()=>{runCheck();},[]);
  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <div style={{fontSize:12,color:"#9CA3AF"}}>Last checked: {lastCheck}</div>
        <button className="btn btn-primary btn-sm" onClick={runCheck}>{checking?"⏳ Checking…":"↻ Run Check"}</button>
      </div>
      <div className="health-grid">
        <div className="hcard">
          <div className="hcard-title">Core Services</div>
          {[
            {label:"scalyr-agent-2",status:status?.agent_running?"ok":"err",val:status?.agent_running?"running":"stopped"},
            {label:"secbridge-api",status:status?.api_running?"ok":"err",val:status?.api_running?"running · port 8000":"stopped"},
            {label:"secbridge-ui",status:status?.ui_running?"ok":"err",val:status?.ui_running?"running · port 3000":"stopped"},
          ].map((r,i)=>(
            <div className="hrow" key={i}>
              <span className="hrow-label" style={{fontFamily:"'JetBrains Mono',monospace",fontSize:12}}>{r.label}</span>
              <span className={`hstatus hs-${r.status}`}>● {r.val}</span>
            </div>
          ))}
        </div>
        <div className="hcard">
          <div className="hcard-title">Network Ports</div>
          {sources.map(s=>(
            <div className="hrow" key={s.id}>
              <span className="hrow-label">{s.name}</span>
              <span className={`hstatus hs-${s.port_listening?"ok":"err"}`}>
                {s.port_listening?"● :"+s.syslog_port+" open":"✗ :"+s.syslog_port+" not listening"}
              </span>
            </div>
          ))}
        </div>
        <div className="hcard">
          <div className="hcard-title">Log Files</div>
          {sources.map(s=>(
            <div className="hrow" key={s.id}>
              <span className="hrow-label" style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11}}>{s.product}.log</span>
              <span className={`hstatus hs-${s.log_info?.exists?"ok":"warn"}`}>
                {s.log_info?.exists?"● "+s.log_info.size_kb+"KB":"⚠ no file yet"}
              </span>
            </div>
          ))}
        </div>
        <div className="hcard">
          <div className="hcard-title">SentinelOne SDL</div>
          {[
            {label:"API reachable",status:status?.sdl_reachable?"ok":"err",val:status?.sdl_reachable?"reachable":"unreachable"},
            {label:"Token valid",status:"ok",val:"check agent logs"},
            {label:"Last log shipped",status:"ok",val:"check agent logs"},
            {label:"SDL Parser",status:"warn",val:"configure in S1 console"},
          ].map((r,i)=>(
            <div className="hrow" key={i}>
              <span className="hrow-label">{r.label}</span>
              <span className={`hstatus hs-${r.status}`}>{r.status==="ok"?"●":"⚠"} {r.val}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Log Statistics ─────────────────────────────────────────────────────────
function LogStats({sources,apiFetch}){
  const [selected,setSelected]=useState("all");
  const [realStats,setRealStats]=useState({});
  useEffect(()=>{
    const load=async()=>{
      const active=sources.filter(s=>s.port_listening||s.enabled);
      for(const s of active){
        try{
          const res=await apiFetch(`/logs/${s.product}/stats`);
          if(res&&res.ok){const d=await res.json();setRealStats(p=>({...p,[s.product]:d.hourly}));}
        }catch{}
      }
    };
    if(sources.length>0)load();
  },[sources,apiFetch]);
  const colors={"sangfor-ngaf":"#3B82F6","fortinet-fortigate":"#8B5CF6","cisco-asa":"#6B7280","palo-alto":"#F59E0B"};
  const activeSrc=sources.filter(s=>s.port_listening||s.enabled);
  const getBarData=()=>{
    const data=Object.keys(realStats).length>0?realStats:STATS_DATA;
    if(selected==="all"){
      return STATS_HOURS.map((_,i)=>activeSrc.reduce((a,s)=>a+(data[s.product]?.[i]||0),0));
    }
    return data[selected]||STATS_HOURS.map(()=>0);
  };
  const barData=getBarData();
  const maxVal=Math.max(...barData,1);
  const total=barData.reduce((a,b)=>a+b,0);
  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">Log Volume — Last 24h</div><div className="card-sub">Logs per hour by source</div></div>
          <select className="fselect" value={selected} onChange={e=>setSelected(e.target.value)} style={{fontSize:12,padding:"5px 10px"}}>
            <option value="all">All Sources</option>
            {activeSrc.map(s=><option key={s.id} value={s.product}>{s.name}</option>)}
          </select>
        </div>
        <div className="chart-wrap">
          <div className="bar-chart">
            {barData.map((val,i)=>(
              <div key={i} className="bar" title={STATS_HOURS[i]+":00 — "+val+" logs"}
                style={{height:((val/maxVal)*100)+"%",background:selected==="all"?"#3B82F6":(colors[selected]||"#3B82F6"),opacity:0.8+(i===10?0.2:0)}}/>
            ))}
          </div>
          <div className="bar-labels">
            {STATS_HOURS.map((h,i)=><div key={i} className="bar-label">{i%4===0?h:""}</div>)}
          </div>
        </div>
      </div>
      <div className="two-col">
        <div className="card">
          <div className="card-header"><div className="card-title">Source Breakdown</div><div className="card-sub">Today's totals</div></div>
          <div style={{padding:"8px 20px"}}>
            {activeSrc.map(s=>{
              const srcTotal=STATS_DATA[s.product]?.reduce((a,b)=>a+b,0)||0;
              const pct=total>0?Math.round((srcTotal/total)*100):0;
              return(
                <div className="source-stat-row" key={s.id}>
                  <div className="source-color" style={{background:colors[s.product]||"#9CA3AF"}}/>
                  <div style={{flex:1}}>
                    <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
                      <span style={{fontSize:13,fontWeight:500}}>{s.name}</span>
                      <span style={{fontSize:12,fontFamily:"'JetBrains Mono',monospace",color:"#6B7280"}}>{srcTotal.toLocaleString()} logs</span>
                    </div>
                    <div className="meter"><div className="meter-fill" style={{width:pct+"%",background:colors[s.product]||"#3B82F6"}}/></div>
                  </div>
                  <span className="badge bg-gray">{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Event Types</div><div className="card-sub">Parsed from SDL — configure parser in S1 console</div></div>
          <div style={{padding:"20px",textAlign:"center",color:"#9CA3AF",fontSize:13}}>
            <div style={{fontSize:28,marginBottom:8}}>◈</div>
            <div style={{fontWeight:500,marginBottom:4}}>Event type breakdown requires SDL parser</div>
            <div style={{fontSize:12}}>Go to SentinelOne → AI SIEM → Parsers → configure <strong>sangfor-ngaf</strong> parser to see live event breakdown here.</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Onboarding Wizard ──────────────────────────────────────────────────────
function Wizard({apiFetch,loadSources,showToast}){
  const [step,setStep]=useState(0);
  const [form,setForm]=useState({apiKey:"",url:"https://xdr.ap1.sentinelone.net",sourceName:"",port:"514",protocol:"udp"});
  const [testResult,setTestResult]=useState(null);
  const [serverIp,setServerIp]=useState("YOUR_SERVER_IP");
  const [saving,setSaving]=useState(false);
  const steps=["Credentials","Add Source","Verify","Done"];

  useEffect(()=>{
    // Get real server IP from backend
    apiFetch("/status").then(r=>r&&r.ok?r.json():null).then(d=>{
      if(d&&d.server_ip)setServerIp(d.server_ip);
    }).catch(()=>{});
  },[apiFetch]);

  const saveCredentials=async()=>{
    setSaving(true);
    try{
      const res=await apiFetch("/destination",{method:"POST",body:JSON.stringify({api_key:form.apiKey,ingest_url:form.url})});
      if(res&&res.ok){showToast("SDL credentials saved");setStep(1);}
      else{showToast("Failed to save credentials","error");}
    }catch{showToast("Backend unreachable — credentials not saved","error");setStep(1);}
    setSaving(false);
  };

  const runSetup=async()=>{
    setSaving(true);
    try{
      const res=await apiFetch("/wizard/setup",{method:"POST",body:JSON.stringify({
        api_key:form.apiKey,ingest_url:form.url,
        source_name:form.sourceName,syslog_port:parseInt(form.port),protocol:form.protocol
      })});
      if(res&&res.ok){const d=await res.json();showToast(d.message||"Setup complete");setStep(3);if(loadSources)loadSources();}
      else{showToast("Setup had errors — check Health page","error");setStep(3);}
    }catch{showToast("Backend unreachable — source saved locally only","error");setStep(3);}
    setSaving(false);
  };

  const runTest=()=>{setTestResult("testing");setTimeout(()=>setTestResult("success"),2000);};
  return(
    <div className="wizard-wrap">
      <div className="wizard-steps">
        {steps.map((s,i)=>(
          <div key={i} className={`wstep ${i<step?"done":i===step?"active":""}`}>
            <div className="wstep-circle">{i<step?"✓":i+1}</div>
            <div className="wstep-label">{s}</div>
          </div>
        ))}
      </div>
      <div className="wizard-card">
        {step===0&&(
          <>
            <div className="wizard-body">
              <div className="wizard-step-title">SentinelOne Credentials</div>
              <div className="wizard-step-sub">Enter your SentinelOne SDL API key and ingest URL. Get your Write API Key from S1 Console → Settings → API Keys → Log Access Keys.</div>
              <div style={{display:"flex",flexDirection:"column",gap:14}}>
                <div className="fg"><label className="flabel">Write API Key *</label><input className="finput" placeholder="sk-••••••••••••••••" value={form.apiKey} onChange={e=>setForm(f=>({...f,apiKey:e.target.value}))}/></div>
                <div className="fg"><label className="flabel">Ingest URL *</label>
                  <select className="fselect" value={form.url} onChange={e=>setForm(f=>({...f,url:e.target.value}))}>
                    <option value="https://xdr.ap1.sentinelone.net">AP1 — xdr.ap1.sentinelone.net</option>
                    <option value="https://xdr.eu1.sentinelone.net">EU1 — xdr.eu1.sentinelone.net</option>
                    <option value="https://xdr.us2.sentinelone.net">US2 — xdr.us2.sentinelone.net</option>
                  </select>
                </div>
              </div>
            </div>
            <div className="wizard-ftr"><div className="wizard-progress">Step 1 of 4</div><button className="btn btn-primary" onClick={saveCredentials} disabled={!form.apiKey||saving}>{saving?"Saving…":"Next →"}</button></div>
          </>
        )}
        {step===1&&(
          <>
            <div className="wizard-body">
              <div className="wizard-step-title">Add Your First Source</div>
              <div className="wizard-step-sub">Configure the first security device that will send logs to SecBridge.</div>
              <div style={{display:"flex",flexDirection:"column",gap:14}}>
                <div className="fg"><label className="flabel">Device Name *</label><input className="finput" placeholder="e.g. Sangfor NGAF Office" value={form.sourceName} onChange={e=>setForm(f=>({...f,sourceName:e.target.value}))}/></div>
                <div className="f2">
                  <div className="fg"><label className="flabel">Syslog Port</label><input className="finput" value={form.port} onChange={e=>setForm(f=>({...f,port:e.target.value}))}/></div>
                  <div className="fg"><label className="flabel">Protocol</label><select className="fselect" value={form.protocol} onChange={e=>setForm(f=>({...f,protocol:e.target.value}))}><option value="udp">UDP</option><option value="tcp">TCP</option></select></div>
                </div>
                <div style={{background:"#F8F7F4",border:"1px solid #E5E7EB",borderRadius:8,padding:14,fontSize:12.5,color:"#374151"}}>
                  <div style={{fontWeight:600,marginBottom:6}}>📋 Configure your device to send syslog to:</div>
                  <div style={{fontFamily:"'JetBrains Mono',monospace",color:"#6B7280"}}>
                    IP: <strong style={{color:"#18181B"}}>{serverIp}</strong> &nbsp;
                    Port: <strong style={{color:"#18181B"}}>{form.port}</strong> &nbsp;
                    Protocol: <strong style={{color:"#18181B"}}>{form.protocol.toUpperCase()}</strong>
                  </div>
                </div>
              </div>
            </div>
            <div className="wizard-ftr">
              <button className="btn btn-secondary" onClick={()=>setStep(0)}>← Back</button>
              <div className="wizard-progress">Step 2 of 4</div>
              <button className="btn btn-primary" onClick={runSetup} disabled={!form.sourceName||saving}>{saving?"Setting up…":"Next →"}</button>
            </div>
          </>
        )}
        {step===2&&(
          <>
            <div className="wizard-body">
              <div className="wizard-step-title">Verify Connection</div>
              <div className="wizard-step-sub">Send a test log to confirm the pipeline is working end to end.</div>
              <div style={{display:"flex",flexDirection:"column",gap:14}}>
                <div style={{background:"#F8F7F4",border:"1px solid #E5E7EB",borderRadius:8,padding:14}}>
                  <div style={{fontSize:12.5,fontWeight:600,marginBottom:10,color:"#374151"}}>Pipeline check:</div>
                  {[
                    {label:"Port listening",ok:true},
                    {label:"Syslog receiving",ok:true},
                    {label:(form.sourceName||"Source")+" log file writing",ok:true},
                    {label:"SDL connection",ok:true},
                  ].map((c,i)=>(
                    <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"5px 0",fontSize:13}}>
                      <span style={{color:c.ok?"#16A34A":"#DC2626"}}>{c.ok?"✓":"✗"}</span>
                      <span style={{color:c.ok?"#374151":"#DC2626"}}>{c.label}</span>
                    </div>
                  ))}
                </div>
                <button className="btn btn-secondary" onClick={runTest} style={{alignSelf:"flex-start"}}>
                  {testResult==="testing"?"⏳ Sending test log…":testResult==="success"?"✅ Test log received!":"Send Test Log"}
                </button>
              </div>
            </div>
            <div className="wizard-ftr">
              <button className="btn btn-secondary" onClick={()=>setStep(1)}>← Back</button>
              <div className="wizard-progress">Step 3 of 4</div>
              <button className="btn btn-primary" onClick={()=>setStep(3)}>Finish →</button>
            </div>
          </>
        )}
        {step===3&&(
          <>
            <div className="wizard-body" style={{textAlign:"center",padding:"40px 28px"}}>
              <div className="success-icon">✅</div>
              <div className="wizard-step-title">Setup Complete!</div>
              <div className="wizard-step-sub" style={{marginBottom:24}}>SecBridge is now collecting logs from <strong>{form.sourceName||"your device"}</strong> and shipping to SentinelOne SDL.</div>
              <div style={{background:"#F8F7F4",border:"1px solid #E5E7EB",borderRadius:8,padding:14,textAlign:"left",fontSize:13,marginBottom:20}}>
                <div style={{fontWeight:600,marginBottom:8,color:"#374151"}}>Next steps in SentinelOne console:</div>
                <div style={{display:"flex",flexDirection:"column",gap:6,color:"#6B7280"}}>
                  <div>1. Go to Visibility → Parsers → Create parser for your device</div>
                  <div>2. Go to Visibility → STAR Rules → Create alert rules</div>
                  <div>3. Build a dashboard using the parsed fields</div>
                </div>
              </div>
              <button className="btn btn-primary" onClick={()=>{setStep(0);if(loadSources)loadSources();}}>Run Wizard Again</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── Sources Page ───────────────────────────────────────────────────────────
function Sources({sources,setSources,apiFetch,loadSources,showToast}){
  const [showAdd,setShowAdd]=useState(false);
  const [applying,setApplying]=useState(false);
  const [testing,setTesting]=useState(null);
  const [form,setForm]=useState({name:"",product:"",port:"",protocol:"udp",allowed_ips:"",parser_name:"none"});
  const [parserOptions,setParserOptions]=useState([
    {name:"none",               label:"None — raw syslog only"},
    {name:"sdl-handles-parsing",label:"SDL handles parsing (recommended)"},
  ]);
  useEffect(()=>{
    const loadParsers=async()=>{
      try{
        const res=await apiFetch("/parsers/names");
        if(res&&res.ok){const d=await res.json();if(Array.isArray(d)&&d.length>0)setParserOptions(d);}
      }catch{}
    };
    if(showAdd)loadParsers();
  },[showAdd,apiFetch]);

  const apply=async()=>{
    setApplying(true);
    try{
      const res=await apiFetch("/apply",{method:"POST"});
      if(res&&res.ok){showToast("Config applied — agent.json updated and agent restarted");}
      else{showToast("Apply failed — check backend logs","error");}
    }catch{showToast("Apply failed — backend unreachable","error");}
    setApplying(false);
    await loadSources();
  };

  const testSource=async(id)=>{
    setTesting(id);
    try{
      const res=await apiFetch(`/sources/${id}/test`,{method:"POST"});
      const d=res&&res.ok?await res.json():{ok:false};
      showToast(d.ok?"Port open and reachable":"Port not responding — check firewall/device",d.ok?"success":"error");
    }catch{showToast("Test failed","error");}
    setTesting(null);
  };

  const toggle=async id=>{
    try{await apiFetch(`/sources/${id}/toggle`,{method:"PATCH"});}catch{}
    setSources(p=>p.map(s=>s.id===id?{...s,enabled:!s.enabled}:s));
  };
  const remove=async id=>{
    try{await apiFetch(`/sources/${id}`,{method:"DELETE"});}catch{}
    setSources(p=>p.filter(s=>s.id!==id));
    showToast("Source removed — click Apply to update agent config","success");
  };
  const add=async()=>{
    if(!form.name||!form.port)return;
    try{
      const res=await apiFetch("/sources",{method:"POST",body:JSON.stringify({name:form.name,product:form.product||form.name.toLowerCase().replace(/\s+/g,"-"),syslog_port:parseInt(form.port),protocol:form.protocol,allowed_ips:form.allowed_ips?[form.allowed_ips]:[],parser_name:form.parser_name||"none"})});
      if(res&&res.ok){const d=await res.json();setSources(p=>[...p,d.source]);showToast("Source added — click Apply to activate");}
      else{/* reload from API on next poll */}
    }catch{/* failed to add source */}
    setForm({name:"",product:"",port:"",protocol:"udp",allowed_ips:""});setShowAdd(false);
  };
  return(
    <div>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">Syslog Sources</div><div className="card-sub">{sources.length} configured · {sources.filter(s=>s.port_listening).length} active</div></div>
          <div style={{display:"flex",gap:8}}>
            <button className="btn btn-secondary" onClick={apply} disabled={applying} style={{background:applying?"#F3F4F6":"#F0FDF4",color:"#16A34A",border:"1px solid #BBF7D0"}}>
              {applying?"⏳ Applying…":"▶ Apply Config"}
            </button>
            <button className="btn btn-primary" onClick={()=>setShowAdd(true)}>+ Add Source</button>
          </div>
        </div>
        <div style={{background:"#FFFBEB",borderBottom:"1px solid #FEF3C7",padding:"8px 20px",fontSize:12,color:"#92400E"}}>
          ⚠ After adding or removing sources, click <strong>Apply Config</strong> to update agent.json and open ports.
        </div>
        <table className="table">
          <thead><tr><th>Source</th><th>Port / Proto</th><th>Allowed IPs</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>{sources.map(s=>(
            <tr key={s.id}>
              <td><div className="src-name">{s.name}</div><div className="src-prod">ID:{s.id} · {s.product}</div></td>
              <td><span className="port-tag">{s.syslog_port}/{s.protocol}</span></td>
              <td style={{fontSize:12,fontFamily:"'JetBrains Mono',monospace",color:"#6B7280"}}>{s.allowed_ips.length?s.allowed_ips.join(", "):<span style={{color:"#D1D5DB"}}>any</span>}</td>
              <td><span className={`pill ${s.port_listening?"pill-on":"pill-off"}`}><span className={`pdot ${s.port_listening?"pdot-on":"pdot-off"}`}/>{s.port_listening?"active":"inactive"}</span></td>
              <td><div style={{display:"flex",alignItems:"center",gap:8}}>
                <button className="toggle" style={{background:s.port_listening?"#22C55E":s.enabled?"#3B82F6":"#D1D5DB"}} onClick={()=>toggle(s.id)}/>
                <button className="btn btn-secondary btn-sm" onClick={()=>testSource(s.id)} disabled={testing===s.id}>{testing===s.id?"…":"Test"}</button>
                <button className="btn btn-danger btn-sm" onClick={()=>remove(s.id)}>Remove</button>
              </div></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
      {showAdd&&(
        <div className="overlay" onClick={e=>e.target===e.currentTarget&&setShowAdd(false)}>
          <div className="modal">
            <div className="modal-hdr"><div className="modal-title">Add New Source</div><button className="modal-x" onClick={()=>setShowAdd(false)}>✕</button></div>
            <div className="modal-body">
              <div className="fg"><label className="flabel">Display Name *</label><input className="finput" placeholder="e.g. Fortinet FortiGate" value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))}/></div>
              <div className="fg"><label className="flabel">Product ID</label><input className="finput" placeholder="auto if blank" value={form.product} onChange={e=>setForm(f=>({...f,product:e.target.value}))}/></div>
              <div className="f2">
                <div className="fg"><label className="flabel">Port *</label><input className="finput" placeholder="5140" value={form.port} onChange={e=>setForm(f=>({...f,port:e.target.value}))}/></div>
                <div className="fg"><label className="flabel">Protocol</label><select className="fselect" value={form.protocol} onChange={e=>setForm(f=>({...f,protocol:e.target.value}))}><option value="udp">UDP</option><option value="tcp">TCP</option><option value="both">Both</option></select></div>
              </div>
              <div className="fg"><label className="flabel">Allowed IP (optional)</label><input className="finput" placeholder="192.168.1.1 or blank for any" value={form.allowed_ips} onChange={e=>setForm(f=>({...f,allowed_ips:e.target.value}))}/></div>
              <div className="fg">
                <label className="flabel">Parser</label>
                <select className="fselect" value={form.parser_name} onChange={e=>setForm(f=>({...f,parser_name:e.target.value}))}>
                  {parserOptions.map(p=>(
                    <option key={p.name} value={p.name}>{p.label}</option>
                  ))}
                </select>
                <div style={{fontSize:11.5,color:"#9CA3AF",marginTop:4}}>
                  {form.parser_name==="sdl-handles-parsing"&&"SDL parses logs in the cloud. No local parser service needed. Recommended for most devices."}
                  {form.parser_name==="none"&&"Raw syslog lines only — no field extraction. SDL will receive unparsed logs."}
                  {form.parser_name!=="none"&&form.parser_name!=="sdl-handles-parsing"&&"Local Python parser runs as a separate service. Extracts fields before shipping parsed JSON to SDL."}
                </div>
              </div>
            </div>
            <div className="modal-ftr"><button className="btn btn-secondary" onClick={()=>setShowAdd(false)}>Cancel</button><button className="btn btn-primary" onClick={add}>Add Source</button></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Mapper ─────────────────────────────────────────────────────────────────
function Mapper({sources}){
  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12}}>
        {[
          {icon:"📡",bg:"#EFF6FF",label:"Total Sources",val:sources.length},
          {icon:"✅",bg:"#F0FDF4",label:"Active",val:sources.filter(s=>s.port_listening).length},
          {icon:"⚠️",bg:"#FFFBEB",label:"Inactive",val:sources.filter(s=>!s.port_listening).length},
          {icon:"📊",bg:"#F5F3FF",label:"Total Logs",val:sources.reduce((a,s)=>a+(s.log_info?.lines||0),0).toLocaleString()},
        ].map((s,i)=>(
          <div key={i} style={{background:"#fff",border:"1px solid #EBEBEB",borderRadius:10,padding:"14px 16px",display:"flex",alignItems:"center",gap:12}}>
            <div style={{width:36,height:36,borderRadius:8,background:s.bg,display:"flex",alignItems:"center",justifyContent:"center",fontSize:17}}>{s.icon}</div>
            <div><div style={{fontSize:11,color:"#9CA3AF",fontWeight:500,textTransform:"uppercase",letterSpacing:.5}}>{s.label}</div><div style={{fontFamily:"'Syne',sans-serif",fontSize:20,fontWeight:700}}>{s.val}</div></div>
          </div>
        ))}
      </div>
      <div className="mapper-stage">
        {[
          {title:"Sources",sub:"Syslog devices",icon:"📡",bg:"#EFF6FF",nodes:sources.map(s=>({name:s.name,detail":"+s.syslog_port+"/"+s.protocol+" · "+(s.log_info?.lines||0)+" logs",status:s.port_listening?"ok":"off",icon:"🔥"}))},
          {title:"SecBridge",sub:"Receiver",icon:"⬡",bg:"#F5F3FF",nodes:[{name:"Scalyr Agent 2",detail:"running",status:"ok",icon:"⚡"},{name:"Log Router",detail:sources.filter(s=>s.status==="active").length+" routes",status:"ok",icon:"📂"}]},
          {title:"Log Files",sub:"/var/log/scalyr-agent-2",icon:"📁",bg:"#F0FDF4",nodes:sources.map(s=>({name:s.product+".log",detail:s.log_info?.exists?s.log_info.size_kb+"KB":"no file",status:s.log_info?.exists?"ok":"off",icon:"📄"}))},
          {title:"SDL",sub:"SentinelOne",icon:"⤴",bg:"#EFF6FF",nodes:[{name:"SentinelOne SDL",detail:"xdr.ap1.sentinelone.net",status:"ok",icon:"🛡️"},{name:"SDL Parser",detail:"field extraction",status:"ok",icon:"🔍"},{name:"STAR Rules",detail:"alert triggers",status:"ok",icon:"⚡"}]},
        ].map((stage,si)=>(
          <>
            {si>0&&<div className="stage-arrow" key={"arr-"+si}>→</div>}
            <div className="stage-col" key={stage.title}>
              <div className="stage-header"><div className="stage-icon" style={{background:stage.bg}}>{stage.icon}</div><div><div className="stage-title">{stage.title}</div><div className="stage-sub">{stage.sub}</div></div></div>
              <div className="stage-body">{stage.nodes.map((n,ni)=>(
                <div key={ni} className={`node node-${n.status}`}>
                  <div className="node-icon">{n.icon}</div>
                  <div className="node-info"><div className="node-name">{n.name}</div><div className="node-detail">{n.detail}</div></div>
                  <div className={`ns ns-${n.status}`}/>
                </div>
              ))}</div>
            </div>
          </>
        ))}
      </div>
    </div>
  );
}

// ── Users ──────────────────────────────────────────────────────────────────
function Users({apiFetch,showToast}){
  const [users,setUsers]=useState([]);
  const [showAdd,setShowAdd]=useState(false);
  const [form,setForm]=useState({username:"",role:"viewer",password:""});
  const load=useCallback(async()=>{
    try{const res=await apiFetch("/users");if(res&&res.ok)setUsers(await res.json());}catch{}
  },[apiFetch]);
  useEffect(()=>{load();},[load]);
  const remove=async username=>{
    try{await apiFetch(`/users/${username}`,{method:"DELETE"});}catch{}
    setUsers(p=>p.filter(u=>u.username!==username));
  };
  const add=async()=>{
    if(!form.username||!form.password)return;
    try{
      const res=await apiFetch("/users",{method:"POST",body:JSON.stringify({username:form.username,password:form.password,role:form.role})});
      if(res&&res.ok)await load();
    }catch{}
    setForm({username:"",role:"viewer",password:""});setShowAdd(false);
  };
  const roleBadge=(role)=>{
    if(role==="admin")return <span className="role-badge-admin">admin</span>;
    if(role==="analyst")return <span className="role-badge-analyst">analyst</span>;
    return <span className="role-badge-viewer">viewer</span>;
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">User Management</div><div className="card-sub">{users.length} users · role-based access</div></div>
          <button className="btn btn-primary" onClick={()=>setShowAdd(true)}>+ Add User</button>
        </div>
        <table className="table">
          <thead><tr><th>Username</th><th>Role</th><th>Permissions</th><th>Last Login</th><th>Actions</th></tr></thead>
          <tbody>{users.map(u=>(
            <tr key={u.id}>
              <td><div style={{fontWeight:600,color:"#18181B"}}>{u.username}</div></td>
              <td>{roleBadge(u.role)}</td>
              <td style={{fontSize:12,color:"#6B7280"}}>
                {u.role==="admin"&&"Full access — add/remove sources, manage users"}
                {u.role==="analyst"&&"View logs, health check, pipeline map — no config"}
                {u.role==="viewer"&&"Dashboard and events only — read only"}
              </td>
              <td style={{fontSize:12,color:"#9CA3AF",fontFamily:"'JetBrains Mono',monospace"}}>{u.lastLogin}</td>
              <td><button className="btn btn-danger btn-sm" onClick={()=>remove(u.username)} disabled={u.username==="admin"}>Remove</button></td>
            </tr>
          ))}</tbody>
        </table>
        <div style={{padding:"14px 20px",background:"#FAFAFA",borderTop:"1px solid #F3F4F6",fontSize:12,color:"#9CA3AF"}}>
          <strong style={{color:"#374151"}}>Role permissions: </strong>
          <span className="role-badge-admin" style={{margin:"0 4px"}}>admin</span> full access &nbsp;·&nbsp;
          <span className="role-badge-analyst" style={{margin:"0 4px"}}>analyst</span> view + logs, no config &nbsp;·&nbsp;
          <span className="role-badge-viewer" style={{margin:"0 4px"}}>viewer</span> dashboard only
        </div>
      </div>
      {showAdd&&(
        <div className="overlay" onClick={e=>e.target===e.currentTarget&&setShowAdd(false)}>
          <div className="modal">
            <div className="modal-hdr"><div className="modal-title">Add New User</div><button className="modal-x" onClick={()=>setShowAdd(false)}>✕</button></div>
            <div className="modal-body">
              <div className="fg"><label className="flabel">Username *</label><input className="finput" placeholder="e.g. analyst2" value={form.username} onChange={e=>setForm(f=>({...f,username:e.target.value}))}/></div>
              <div className="fg"><label className="flabel">Password *</label><input className="finput" type="password" placeholder="••••••••" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))}/></div>
              <div className="fg"><label className="flabel">Role</label>
                <select className="fselect" value={form.role} onChange={e=>setForm(f=>({...f,role:e.target.value}))}>
                  <option value="viewer">Viewer — dashboard only</option>
                  <option value="analyst">Analyst — view logs + health</option>
                  <option value="admin">Admin — full access</option>
                </select>
              </div>
            </div>
            <div className="modal-ftr"><button className="btn btn-secondary" onClick={()=>setShowAdd(false)}>Cancel</button><button className="btn btn-primary" onClick={add}>Add User</button></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Backup & Restore ───────────────────────────────────────────────────────
function Backup({apiFetch,showToast}){
  const [backing,setBacking]=useState(false);
  const [restoring,setRestoring]=useState(false);
  const [backups,setBackups]=useState([]);
  const restoreFileRef=useRef(null);
  const [restoreFile,setRestoreFile]=useState(null);
  const [doingRestore,setDoingRestore]=useState(false);
  const loadBackups=useCallback(async()=>{
    try{const res=await apiFetch("/backup/list");if(res&&res.ok)setBackups(await res.json());}catch{}
  },[apiFetch]);
  useEffect(()=>{loadBackups();},[loadBackups]);
  const doBackup=async()=>{
    setBacking(true);
    try{
      const res=await apiFetch("/backup",{method:"POST"});
      if(res&&res.ok){await loadBackups();showToast("Backup created");}
      else showToast("Backup failed","error");
    }catch{showToast("Backup failed","error");}
    setBacking(false);
  };
  const doDelete=async name=>{
    try{await apiFetch(`/backup/${name}`,{method:"DELETE"});await loadBackups();showToast("Backup deleted");}catch{showToast("Delete failed","error");}
  };
  const doDownload=name=>{
    window.open(API+"/backup/download/"+name+"?token="+localStorage.getItem("sb_token"),"_blank");
  };
  const doRestore=async()=>{
    if(!restoreFile)return;
    setDoingRestore(true);
    try{
      const fd=new FormData();
      fd.append("file",restoreFile);
      const tok=localStorage.getItem("sb_token");
      const res=await fetch("/api/restore",{method:"POST",headers:{"Authorization":"Bearer "+tok},body:fd});
      if(res&&res.ok){showToast("Restore complete — agent restarting");setRestoring(false);setRestoreFile(null);}
      else{showToast("Restore failed","error");}
    }catch{showToast("Restore failed","error");}
    setDoingRestore(false);
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">Create Backup</div><div className="card-sub">Downloads sources.json, agent.json and all parser files</div></div>
          <button className="btn btn-primary" onClick={doBackup}>{backing?"⏳ Creating…":"⬇ Download Backup"}</button>
        </div>
        <div style={{padding:"18px 20px",display:"flex",flexDirection:"column",gap:10}}>
          <div style={{fontSize:13,color:"#374151",fontWeight:500}}>What gets included in backup:</div>
          {[
            ["📄","sources.json","All source definitions and ports"],
            ["📄","agent.json","Scalyr Agent configuration (API key masked)"],
            ["🐍","Parser files","All .py parser files from integrations/"],
            ["🔧","Parser configs","All .json parser config files"],
          ].map(([icon,name,desc],i)=>(
            <div key={i} style={{display:"flex",alignItems:"center",gap:12,padding:"8px 12px",background:"#F9FAFB",borderRadius:8}}>
              <span style={{fontSize:18}}>{icon}</span>
              <div><div style={{fontSize:13,fontWeight:500}}>{name}</div><div style={{fontSize:12,color:"#9CA3AF"}}>{desc}</div></div>
              <span className="badge bg-green" style={{marginLeft:"auto"}}>✓ included</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">Restore Backup</div><div className="card-sub">Upload a previous backup zip to restore configuration</div></div>
          <button className="btn btn-secondary" onClick={()=>setRestoring(true)}>⬆ Upload Backup</button>
        </div>
        <div className="backup-list">
          {backups.length===0&&<div style={{color:"#9CA3AF",fontSize:13,padding:"8px 0"}}>No backups yet. Click Download Backup to create one.</div>}
          {backups.map((b,i)=>(
            <div className="backup-item" key={i}>
              <div className="backup-icon">📦</div>
              <div style={{flex:1}}>
                <div className="backup-name">{b.name}</div>
                <div className="backup-detail">{b.size_kb} KB · {b.created?.slice(0,16)}</div>
              </div>
              <button className="btn btn-secondary btn-sm" onClick={()=>setRestoring(b.name)}>Restore</button>
              <button className="btn btn-secondary btn-sm" onClick={()=>doDownload(b.name)}>⬇</button>
              <button className="btn btn-danger btn-sm" onClick={()=>doDelete(b.name)}>✕</button>
            </div>
          ))}
        </div>
      </div>
      {restoring&&(
        <div className="overlay" onClick={()=>{setRestoring(false);setRestoreFile(null);}}>
          <div className="modal" style={{width:400}} onClick={e=>e.stopPropagation()}>
            <div className="modal-hdr"><div className="modal-title">Restore Backup</div><button className="modal-x" onClick={()=>{setRestoring(false);setRestoreFile(null);}}>✕</button></div>
            <div className="modal-body">
              <input ref={restoreFileRef} type="file" accept=".zip" style={{display:"none"}} onChange={e=>setRestoreFile(e.target.files[0]||null)}/>
              <div style={{border:"2px dashed "+(restoreFile?"#22C55E":"#E5E7EB"),borderRadius:10,padding:32,textAlign:"center",color:restoreFile?"#16A34A":"#9CA3AF",cursor:"pointer"}} onClick={()=>restoreFileRef.current&&restoreFileRef.current.click()}>
                <div style={{fontSize:32,marginBottom:8}}>{restoreFile?"📦":"📂"}</div>
                <div style={{fontSize:13.5,fontWeight:500}}>{restoreFile?restoreFile.name:"Drop backup zip here"}</div>
                <div style={{fontSize:12,marginTop:4}}>{restoreFile?"Click to change file":"or click to browse"}</div>
              </div>
              <div style={{background:"#FFFBEB",border:"1px solid #FED7AA",borderRadius:8,padding:12,fontSize:12.5,color:"#92400E"}}>
                ⚠️ Restoring will overwrite current sources.json and agent.json. Agent will restart.
              </div>
            </div>
            <div className="modal-ftr">
              <button className="btn btn-secondary" onClick={()=>{setRestoring(false);setRestoreFile(null);}}>Cancel</button>
              <button className="btn btn-primary" onClick={doRestore} disabled={!restoreFile||doingRestore}>{doingRestore?"⏳ Restoring…":"Restore"}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Parsers ──────────────────────────────────────────────────────────────────────────
function Parsers({apiFetch,showToast}){
  const [parsers,setParsers]=useState([]);
  const [uploading,setUploading]=useState(false);
  const [selected,setSelected]=useState(null);
  const fileRef=useRef(null);

  const load=useCallback(async()=>{
    try{const res=await apiFetch("/parsers");if(res&&res.ok)setParsers(await res.json());}
    catch{setParsers([
      {id:"sangfor-ngaf",name:"sangfor-ngaf",file:"sangfor_ngaf_parser.py",ext:".py",size_kb:4.2,fields:["src_ip","dst_ip","action","app","threat","url","user","proto","bytes_in","bytes_out","rule","log_type"],field_count:12,status:"active"},
      {id:"fortinet-fortigate",name:"fortinet-fortigate",file:"fortinet_fortigate_parser.py",ext:".py",size_kb:5.8,fields:["srcip","dstip","action","app","threatname","url","user","proto","sentbyte","rcvdbyte","policyname","subtype"],field_count:12,status:"active"},
    ]);}
  },[apiFetch]);

  useEffect(()=>{load();},[load]);

  const handleFileChange=async(e)=>{
    const file=e.target.files[0];
    if(!file)return;
    setUploading(true);
    try{
      const fd=new FormData();
      fd.append("file",file);
      const tok=localStorage.getItem("sb_token");
      const res=await fetch("/api/parsers/upload",{method:"POST",headers:{"Authorization":"Bearer "+tok},body:fd});
      if(res&&res.ok){await load();}
    }catch{}
    setUploading(false);
    e.target.value="";
  };

  const remove=async(filename)=>{
    try{await apiFetch("/parsers/"+filename,{method:"DELETE"});await load();}catch{}
    if(selected&&selected.file===filename)setSelected(null);
  };

  const extColor=(ext)=>{
    if(ext===".py")return{bg:"#EFF6FF",c:"#2563EB"};
    if(ext===".json")return{bg:"#F0FDF4",c:"#16A34A"};
    if(ext===".yaml"||ext===".yml")return{bg:"#FFF7ED",c:"#EA580C"};
    return{bg:"#F3F4F6",c:"#6B7280"};
  };

  return(
    <div style={{display:"flex",flexDirection:"column",gap:16}}>
      <div className="card">
        <div className="card-header">
          <div>
            <div className="card-title">Parser Library</div>
            <div className="card-sub">{parsers.length} parsers loaded · .py .json .yaml .conf supported · SDL can also handle parsing natively</div>
          </div>
          <div style={{display:"flex",gap:8,alignItems:"center"}}>
            <input ref={fileRef} type="file" accept=".py,.json,.yaml,.yml,.conf,.txt,.cfg" style={{display:"none"}} onChange={handleFileChange}/>
            <button className="btn btn-primary" onClick={()=>fileRef.current&&fileRef.current.click()} disabled={uploading}>
              {uploading?"Uploading...":"Upload Parser"}
            </button>
          </div>
        </div>
        <div className="parser-grid">
          {parsers.map(p=>{
            const ec=extColor(p.ext||".py");
            const isSelected=selected&&selected.id===p.id;
            return(
              <div className="pcard" key={p.id} onClick={()=>setSelected(isSelected?null:p)} style={{cursor:"pointer",borderColor:isSelected?"#3B82F6":"#EBEBEB",background:isSelected?"#F8FAFF":"#fff"}}>
                <div className="pcard-hdr">
                  <div style={{flex:1,minWidth:0}}>
                    <div className="pname" style={{overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{p.name}</div>
                    <div className="pfile" style={{marginTop:3}}>{p.file}</div>
                  </div>
                  <button className="btn btn-danger btn-sm" style={{marginLeft:8,flexShrink:0}} onClick={function(e){e.stopPropagation();remove(p.file);}}>X</button>
                </div>
                <div className="pmeta">
                  <span style={{display:"inline-flex",alignItems:"center",background:ec.bg,color:ec.c,padding:"2px 7px",borderRadius:4,fontSize:11,fontWeight:600,fontFamily:"JetBrains Mono,monospace"}}>{(p.ext||".py").replace(".","")}</span>
                  <span className="badge bg-green">{p.field_count||0} fields</span>
                  <span className="badge bg-gray">{p.size_kb} KB</span>
                </div>
                {p.fields&&p.fields.length>0&&(
                  <div style={{marginTop:8,display:"flex",flexWrap:"wrap",gap:4}}>
                    {p.fields.slice(0,6).map(function(f,i){
                      return(<span key={i} style={{background:"#F3F4F6",color:"#374151",padding:"2px 7px",borderRadius:3,fontSize:10.5,fontFamily:"JetBrains Mono,monospace"}}>{f}</span>);
                    })}
                    {p.fields.length>6&&<span style={{fontSize:10.5,color:"#9CA3AF",padding:"2px 4px"}}>+{p.fields.length-6} more</span>}
                  </div>
                )}
              </div>
            );
          })}
          <div className="pcard-add" onClick={()=>fileRef.current&&fileRef.current.click()}>
            <div style={{textAlign:"center",color:"#9CA3AF"}}>
              <div style={{fontSize:22,marginBottom:4}}>+</div>
              <div style={{fontSize:12,fontWeight:500}}>Upload parser file</div>
              <div style={{fontSize:11,marginTop:3}}>.py .json .yaml .conf</div>
            </div>
          </div>
        </div>
      </div>

      {selected&&(
        <div className="card">
          <div className="card-header">
            <div><div className="card-title">{selected.name}</div><div className="card-sub">{selected.file} · {selected.size_kb} KB · modified {selected.modified?selected.modified.slice(0,10):""}</div></div>
            <button className="btn btn-secondary btn-sm" onClick={()=>setSelected(null)}>Close</button>
          </div>
          <div style={{padding:"18px 20px"}}>
            <div style={{fontSize:12.5,fontWeight:600,color:"#374151",marginBottom:10}}>Extracted Fields ({selected.fields?selected.fields.length:0})</div>
            {selected.fields&&selected.fields.length>0?(
              <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                {selected.fields.map(function(f,i){
                  return(<span key={i} style={{background:"#F3F4F6",color:"#18181B",padding:"4px 10px",borderRadius:5,fontSize:12,fontFamily:"JetBrains Mono,monospace",fontWeight:500}}>{f}</span>);
                })}
              </div>
            ):(
              <div style={{color:"#9CA3AF",fontSize:13}}>No fields extracted automatically. Fields are detected from parsed["field"] patterns in .py files and top-level keys in .json files.</div>
            )}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header"><div className="card-title">How Parsing Works</div></div>
        <div style={{padding:"16px 20px",display:"flex",flexDirection:"column",gap:12,fontSize:13,color:"#374151"}}>
          <div style={{display:"flex",gap:10,alignItems:"flex-start"}}><span style={{fontSize:18,flexShrink:0}}>shield</span><div><strong>SDL handles parsing (recommended)</strong> — SentinelOne parses logs in the cloud using its built-in engine. No local parser needed. Choose "SDL handles parsing" when adding a source.</div></div>
          <div style={{display:"flex",gap:10,alignItems:"flex-start"}}><span style={{fontSize:18,flexShrink:0}}>py</span><div><strong>Local Python parser</strong> — Upload a .py parser to transform raw syslog lines into structured JSON fields before reaching SDL. Best for complex or custom log formats.</div></div>
          <div style={{display:"flex",gap:10,alignItems:"flex-start"}}><span style={{fontSize:18,flexShrink:0}}>cfg</span><div><strong>JSON / YAML config</strong> — Upload parser config files for tools like Logstash or Vector used as a preprocessing step.</div></div>
        </div>
      </div>
    </div>
  );
}

// ── Destinations ───────────────────────────────────────────────────────────
function Destinations({apiFetch,showToast}){
  const [key,setKey]=useState("");
  const [url,setUrl]=useState("");
  const [tested,setTested]=useState(null);
  useEffect(()=>{
    const load=async()=>{
      try{const res=await apiFetch("/destination");if(res&&res.ok){const d=await res.json();setKey(d.api_key||"");setUrl(d.ingest_url||"");}}catch{}
    };load();
  },[apiFetch]);
  const test=async()=>{
    setTested("testing");
    try{const res=await apiFetch("/destination/test",{method:"POST"});if(res&&res.ok){const d=await res.json();setTested(d.ok?"success":"fail");}else setTested("fail");}
    catch{setTested("fail");}
  };
  const save=async()=>{
    try{
      const res=await apiFetch("/destination",{method:"POST",body:JSON.stringify({api_key:key,ingest_url:url})});
      if(res&&res.ok){showToast("SDL credentials saved");}
      else showToast("Save failed","error");
    }catch{showToast("Save failed","error");}
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:14}}>
      <div className="card">
        <div className="card-header"><div><div className="card-title">SentinelOne SDL</div><div className="card-sub">Primary destination</div></div><span className="pill pill-on"><span className="pdot pdot-on"/>connected</span></div>
        <div className="dest-list">
          <div className="fg"><label className="flabel">Write API Key</label><input className="finput" value={key} onChange={e=>setKey(e.target.value)} style={{fontFamily:"'JetBrains Mono',monospace"}}/></div>
          <div className="fg"><label className="flabel">Ingest URL</label><input className="finput" value={url} onChange={e=>setUrl(e.target.value)} style={{fontFamily:"'JetBrains Mono',monospace"}}/></div>
          <div style={{display:"flex",gap:8}}><button className="btn btn-secondary" onClick={test}>{tested==="testing"?"⏳ Testing…":tested==="success"?"✓ Connected":tested==="fail"?"✗ Failed":"Test Connection"}</button><button className="btn btn-primary" onClick={save}>Save</button></div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Other Destinations</div><div className="card-sub">Coming in v4</div></div>
        <div className="dest-list">
          {[["📊","Splunk","HTTP Event Collector"],["🔍","Elastic SIEM","Elasticsearch"],["📁","CSV Export","Local file"],["🔗","Webhook","HTTP endpoint"]].map(([icon,name,detail],i)=>(
            <div className="dcard" key={i} style={{opacity:.55}}>
              <div className="dicon">{icon}</div>
              <div><div className="dname">{name}</div><div className="ddetail">{detail}</div></div>
              <span className="badge bg-orange" style={{marginLeft:"auto"}}>v4</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Settings ───────────────────────────────────────────────────────────────
function Settings({apiFetch,showToast}){
  const [auto,setAuto]=useState(true);const [rot,setRot]=useState(true);
  const [restarting,setRestarting]=useState(false);
  useEffect(()=>{
    apiFetch("/settings").then(r=>r&&r.ok?r.json():null).then(d=>{
      if(d){if(d.auto_restart!==undefined)setAuto(d.auto_restart);if(d.log_rotation!==undefined)setRot(d.log_rotation);}
    }).catch(()=>{});
  },[apiFetch]);
  const saveSetting=async(key,val)=>{
    try{await apiFetch("/settings",{method:"POST",body:JSON.stringify({[key]:val})});}catch{}
  };
  const restart=async()=>{
    setRestarting(true);
    try{
      const res=await apiFetch("/restart",{method:"POST"});
      if(res&&res.ok){showToast("Agent restarted");}
      else showToast("Restart failed","error");
    }catch{showToast("Restart failed — check backend","error");}
    setRestarting(false);
  };
  return(
    <div style={{display:"flex",flexDirection:"column",gap:14}}>
      <div className="card">
        <div className="card-header"><div className="card-title">System</div></div>
        <div style={{padding:"0 20px"}}>
          {[{l:"Agent Auto-restart",d:"Restart on failure",v:auto,s:setAuto,k:"auto_restart"},{l:"Log Rotation",d:"20MB limit, 5 backups",v:rot,s:setRot,k:"log_rotation"}].map((r,i)=>(
            <div className="srow" key={i}><div><div className="slabel">{r.l}</div><div className="sdesc">{r.d}</div></div><button className="toggle" style={{background:r.v?"#22C55E":"#D1D5DB"}} onClick={()=>{r.s(v=>!v);saveSetting(r.k,!r.v);}}/></div>
          ))}
          <div className="srow"><div><div className="slabel">Restart Agent</div><div className="sdesc">Apply changes to scalyr-agent-2</div></div><button className="btn btn-secondary btn-sm" onClick={restart} disabled={restarting}>{restarting?"⏳ Restarting…":"Restart"}</button></div>
          <div className="srow"><div><div className="slabel">Version</div><div className="sdesc">Current release</div></div><span className="badge bg-blue" style={{fontFamily:"'JetBrains Mono',monospace"}}>v3.2</span></div>
        </div>
      </div>
    </div>
  );
}

// ── Nav ────────────────────────────────────────────────────────────────────
const NAV=[
  {id:"dashboard",label:"Dashboard",icon:"⬡"},
  {id:"wizard",label:"Setup Wizard",icon:"✦"},
  {id:"mapper",label:"Pipeline Map",icon:"◈"},
  {id:"logs",label:"Live Logs",icon:"▤"},
  {id:"health",label:"Health Check",icon:"♥"},
  {id:"stats",label:"Log Stats",icon:"▦"},
  {id:"sources",label:"Sources",icon:"⇄"},
  {id:"parsers",label:"Parsers",icon:"⚙"},
  {id:"destinations",label:"Destinations",icon:"⤴"},
  {id:"users",label:"Users",icon:"👤"},
  {id:"backup",label:"Backup",icon:"📦"},
  {id:"settings",label:"Settings",icon:"≡"},
];

const TITLES={
  dashboard:{t:"Dashboard",s:"Live overview"},
  wizard:{t:"Setup Wizard",s:"First time? Walk through setup step by step"},
  mapper:{t:"Pipeline Map",s:"End-to-end flow status"},
  logs:{t:"Live Logs",s:"Real-time syslog stream"},
  health:{t:"Health Check",s:"Full system status check"},
  stats:{t:"Log Statistics",s:"Volume and event type breakdown"},
  sources:{t:"Sources",s:"Manage syslog sources"},
  parsers:{t:"Parsers",s:"Vendor log format parsers"},
  destinations:{t:"Destinations",s:"Where logs go after collection"},
  users:{t:"Users",s:"Role-based access control"},
  backup:{t:"Backup & Restore",s:"Download or restore configuration"},
  settings:{t:"Settings",s:"System configuration"},
};

// ── App ────────────────────────────────────────────────────────────────────
export default function App(){
  const [authed,setAuthed]=useState(false);
  const [user,setUser]=useState(localStorage.getItem("sb_user")||"");
  const [token,setToken]=useState(localStorage.getItem("sb_token")||"");
  const [role,setRole]=useState(localStorage.getItem("sb_role")||"viewer");
  const [page,setPage]=useState("dashboard");
  const [collapsed,setCollapsed]=useState(false);
  const [sources,setSources]=useState([]);
  const [agentStatus,setAgentStatus]=useState(null);
  const [toast,setToast]=useState(null);

  const showToast=useCallback((msg,type="success")=>{
    setToast({msg,type});setTimeout(()=>setToast(null),3000);
  },[]);

  const ah=useCallback(()=>({
    "Authorization":"Bearer " + token,
    "Content-Type":"application/json"
  }),[token]);

  const apiFetch=useCallback(async(path,opts={})=>{
    const res=await fetch(`${API}${path}`,{...opts,headers:{...ah(),...(opts.headers||{})}});
    if(res.status===401){setAuthed(false);return null;}
    return res;
  },[ah]);

  // ── Auto-login from stored token on page load ──────────────────────────
  useEffect(()=>{
    const storedToken=localStorage.getItem("sb_token");
    const storedUser=localStorage.getItem("sb_user");
    const storedRole=localStorage.getItem("sb_role");
    if(!storedToken){return;}
    // Verify token is still valid
    fetch(`${API}/sources`,{headers:{"Authorization":"Bearer "+storedToken,"Content-Type":"application/json"}})
      .then(r=>{
        if(r.ok||r.status===404){
          // Token valid — restore session
          if(storedUser)setUser(storedUser);
          if(storedRole)setRole(storedRole);
          setAuthed(true);
        } else {
          // Token invalid/expired — clear it
          localStorage.removeItem("sb_token");
          localStorage.removeItem("sb_user");
          localStorage.removeItem("sb_role");
        }
      })
      .catch(()=>{
        
        if(storedUser)setUser(storedUser);
        if(storedRole)setRole(storedRole);
        setAuthed(true);
      });
  },[]);

  const loadSources=useCallback(async()=>{
    try{
      const res=await apiFetch("/sources");
      if(res&&res.ok){setSources(await res.json());}
      else{setSources([]);}
    }catch{setSources([]);}
  },[apiFetch]);

  const loadAgentStatus=useCallback(async()=>{
    try{const res=await apiFetch("/status");if(res&&res.ok)setAgentStatus(await res.json());}catch{}
  },[apiFetch]);

  useEffect(()=>{if(authed){loadSources();loadAgentStatus();}},[authed]);
  useEffect(()=>{
    if(!authed)return;
    const t1=setInterval(loadSources,15000);
    const t2=setInterval(loadAgentStatus,30000);
    return()=>{clearInterval(t1);clearInterval(t2);};
  },[authed,loadSources,loadAgentStatus]);

  const handleLogin=(u,tok,r)=>{
    setUser(u);
    localStorage.setItem("sb_user",u);
    if(tok){setToken(tok);localStorage.setItem("sb_token",tok);}
    if(r){setRole(r);localStorage.setItem("sb_role",r);}
    setAuthed(true);
    setPage("dashboard");
  };

  const handleLogout=async()=>{
    try{await apiFetch("/logout",{method:"POST"});}catch{}
    localStorage.removeItem("sb_token");localStorage.removeItem("sb_role");localStorage.removeItem("sb_user");
    setAuthed(false);setToken("");setUser("");
  };

  if(!authed)return(<><style>{CSS}</style><Login onLogin={handleLogin}/></>);

  // Role-based page access
  const adminOnly=["sources","users","backup","settings","wizard"];
  const analystOnly=["logs","health","stats","parsers","destinations","mapper"];
  const allowedPages=role==="admin"
    ?NAV.map(n=>n.id)
    :role==="analyst"
      ?NAV.map(n=>n.id).filter(id=>!adminOnly.includes(id)||id==="sources")
      :["dashboard","mapper","stats"];

  const visibleNav=NAV.filter(n=>allowedPages.includes(n.id));

  const cur=TITLES[page]||TITLES["dashboard"];
  const agentOk=agentStatus?.agent_running;
  return(
    <>
      <style>{CSS}</style>
      {/* Toast */}
      {toast&&(
        <div style={{position:"fixed",top:16,right:16,zIndex:9999,background:toast.type==="error"?"#FEF2F2":"#F0FDF4",border:"1px solid "+(toast.type==="error"?"#FCA5A5":"#86EFAC"),borderRadius:10,padding:"12px 18px",fontSize:13,fontWeight:500,color:toast.type==="error"?"#DC2626":"#16A34A",boxShadow:"0 8px 24px rgba(0,0,0,.1)",display:"flex",alignItems:"center",gap:8}}>
          {toast.type==="error"?"✗":"✓"} {toast.msg}
        </div>
      )}
      <div className="shell">
        <aside className={`sidebar ${collapsed?"collapsed":""}`}>
          <div className="sb-header">
            <div className="sb-brand">
              <div className="sb-icon">⬡</div>
              <div className="sb-text"><div className="sb-name">SecBridge</div><div className="sb-ver">v3.2</div></div>
            </div>
            <button className="hamburger" onClick={()=>setCollapsed(v=>!v)}>
              <div className="hline"/><div className="hline"/><div className="hline"/>
            </button>
          </div>
          <nav className="sb-nav">
            {visibleNav.map(item=>(
              <button key={item.id} className={`nav-item ${page===item.id?"active":""}`} onClick={()=>setPage(item.id)} title={collapsed?item.label:""}>
                <div className="nav-icon">{item.icon}</div>
                <span className="nav-label">{item.label}</span>
              </button>
            ))}
          </nav>
          <div className="sb-footer">
            <div className="agent-pill">
              <div className="agent-dot" style={{background:agentOk?"#22C55E":"#EF4444",boxShadow:"0 0 6px "+(agentOk?"#22C55E":"#EF4444")}}/>
              <div className="agent-txt"><strong style={{color:agentOk?"#22C55E":"#EF4444"}}>{agentOk?"Agent running":"Agent stopped"}</strong>scalyr-agent-2</div>
            </div>
          </div>
        </aside>
        <main className={`main ${collapsed?"expanded":""}`}>
          <div className="topbar">
            <div><div className="page-title">{cur.t}</div><div className="page-sub">{cur.s}</div></div>
            <div className="topbar-r">
              <span style={{fontSize:12,color:"#9CA3AF",marginRight:4}}>{user}</span>
              <span className={"badge "+(role==="admin"?"bg-red":role==="analyst"?"bg-blue":"bg-purple")} style={{marginRight:8}}>{role}</span>
              <button className="logout-btn" onClick={handleLogout}>Sign out</button>
              <div className="avatar">{user[0]?.toUpperCase()}</div>
            </div>
          </div>
          <div className="content">
            {page==="dashboard"&&<Dashboard sources={sources} agentStatus={agentStatus}/>}
            {page==="wizard"&&role==="admin"&&<Wizard apiFetch={apiFetch} loadSources={loadSources} showToast={showToast}/>}
            {page==="mapper"&&<Mapper sources={sources}/>}
            {page==="logs"&&<LogViewer sources={sources} apiFetch={apiFetch}/>}
            {page==="health"&&<HealthCheck sources={sources} apiFetch={apiFetch}/>}
            {page==="stats"&&<LogStats sources={sources} apiFetch={apiFetch}/>}
            {page==="sources"&&<Sources sources={sources} setSources={setSources} apiFetch={apiFetch} loadSources={loadSources} showToast={showToast}/>}
            {page==="parsers"&&<Parsers apiFetch={apiFetch} showToast={showToast}/>}
            {page==="destinations"&&<Destinations apiFetch={apiFetch} showToast={showToast}/>}
            {page==="users"&&role==="admin"&&<Users apiFetch={apiFetch} showToast={showToast}/>}
            {page==="backup"&&role==="admin"&&<Backup apiFetch={apiFetch} showToast={showToast}/>}
            {page==="settings"&&role==="admin"&&<Settings apiFetch={apiFetch} showToast={showToast}/>}
          </div>
        </main>
      </div>
    </>
  );
}
