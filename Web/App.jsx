import { useState, useEffect, useRef, useCallback } from "react";

// ── API ────────────────────────────────────────────────────────────────────
const API = "/api"; // proxied by Vite → http://localhost:8000

// Fallback mock data shown when API is unreachable
const MOCK_SOURCES = [
  { id:"001", name:"Sangfor NGAF", product:"sangfor-ngaf", port:514, protocol:"UDP", status:"active", logsPerMin:142, allowed_ips:[], lastSeen:"2s ago", parser:"sangfor-ngaf", errors:0 },
  { id:"002", name:"Fortinet FortiGate", product:"fortinet-fortigate", port:5140, protocol:"UDP", status:"active", logsPerMin:87, allowed_ips:["192.168.10.1"], lastSeen:"1s ago", parser:"fortinet-fortigate", errors:2 },
  { id:"003", name:"Cisco ASA", product:"cisco-asa", port:5141, protocol:"TCP", status:"inactive", logsPerMin:0, allowed_ips:["10.0.0.1"], lastSeen:"14m ago", parser:"none", errors:0 },
];

const MOCK_EVENTS = [
  { time:"10:47:02", source:"Sangfor NGAF", type:"THREAT", msg:"APT Botnet detected — src 10.8.2.201", severity:"critical" },
  { time:"10:46:58", source:"Fortinet FortiGate", type:"BLOCK", msg:"Outbound connection blocked — dst 45.33.32.156", severity:"high" },
  { time:"10:46:51", source:"Palo Alto PAN-OS", type:"IPS", msg:"SQL Injection attempt — src 192.168.5.44", severity:"high" },
  { time:"10:46:44", source:"Sangfor NGAF", type:"AUTH", msg:"Failed login — user john.doe from 10.1.1.55", severity:"medium" },
  { time:"10:46:39", source:"Fortinet FortiGate", type:"TRAFFIC", msg:"Allowed — Gmail browse 18.4KB out", severity:"low" },
  { time:"10:46:31", source:"Sangfor NGAF", type:"URL", msg:"Malicious URL blocked — malware-site.com", severity:"critical" },
];

const MOCK_PARSERS = [
  { id:"p001", name:"sangfor-ngaf", vendor:"Sangfor", format:"fwlog", status:"active", fields:12, file:"sangfor_ngaf.py" },
  { id:"p002", name:"fortinet-fortigate", vendor:"Fortinet", format:"CEF", status:"active", fields:18, file:"fortinet_fortigate.py" },
  { id:"p003", name:"cisco-asa", vendor:"Cisco", format:"Syslog", status:"inactive", fields:9, file:"cisco_asa.py" },
  { id:"p004", name:"palo-alto", vendor:"Palo Alto", format:"CEF", status:"active", fields:15, file:"palo_alto.py" },
];

const SEV = {
  critical:{ bg:"#FEF2F2", text:"#DC2626", dot:"#DC2626" },
  high:    { bg:"#FFF7ED", text:"#EA580C", dot:"#EA580C" },
  medium:  { bg:"#FFFBEB", text:"#D97706", dot:"#D97706" },
  low:     { bg:"#F0FDF4", text:"#16A34A", dot:"#16A34A" },
};

// ── Styles ─────────────────────────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Outfit:wght@300;400;500;600&display=swap');

*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Outfit',sans-serif;background:#F5F4F1;color:#18181B;overflow-x:hidden;}

/* ── Login ── */
.login-wrap{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(135deg,#18181B 0%,#1e3a5f 50%,#18181B 100%);
  position:relative;overflow:hidden;
}
.login-bg-grid{
  position:absolute;inset:0;
  background-image:linear-gradient(rgba(255,255,255,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(255,255,255,.03) 1px,transparent 1px);
  background-size:48px 48px;
}
.login-glow{
  position:absolute;width:600px;height:600px;
  background:radial-gradient(circle,rgba(59,130,246,.12) 0%,transparent 70%);
  top:50%;left:50%;transform:translate(-50%,-50%);
  pointer-events:none;
}
.login-card{
  position:relative;z-index:2;
  background:rgba(255,255,255,.97);
  border-radius:20px;
  width:400px;
  padding:40px;
  box-shadow:0 32px 80px rgba(0,0,0,.35);
}
.login-logo{
  display:flex;align-items:center;gap:12px;margin-bottom:32px;
}
.login-logo-icon{
  width:42px;height:42px;border-radius:10px;
  background:linear-gradient(135deg,#1e3a5f,#3B82F6);
  display:flex;align-items:center;justify-content:center;
  font-size:20px;color:white;
}
.login-logo-name{font-family:'Syne',sans-serif;font-size:22px;font-weight:700;color:#18181B;}
.login-logo-ver{font-size:11px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:1px;}
.login-title{font-family:'Syne',sans-serif;font-size:24px;font-weight:700;margin-bottom:6px;}
.login-sub{font-size:13.5px;color:#6B7280;margin-bottom:28px;}
.login-field{display:flex;flex-direction:column;gap:6px;margin-bottom:16px;}
.login-label{font-size:12.5px;font-weight:500;color:#374151;}
.login-input{
  padding:10px 14px;border:1.5px solid #E5E7EB;border-radius:9px;
  font-size:14px;font-family:'Outfit',sans-serif;outline:none;
  transition:all .15s;background:#FAFAFA;
}
.login-input:focus{border-color:#3B82F6;background:#fff;box-shadow:0 0 0 3px rgba(59,130,246,.1);}
.login-btn{
  width:100%;padding:11px;background:#18181B;color:#fff;border:none;
  border-radius:9px;font-size:14px;font-weight:600;font-family:'Outfit',sans-serif;
  cursor:pointer;margin-top:8px;transition:background .15s;letter-spacing:.3px;
}
.login-btn:hover{background:#2d2d4a;}
.login-err{
  background:#FEF2F2;color:#DC2626;border-radius:7px;
  padding:10px 14px;font-size:13px;margin-bottom:14px;
}
.login-footer{text-align:center;font-size:12px;color:#9CA3AF;margin-top:20px;}

/* ── App Shell ── */
.shell{display:flex;min-height:100vh;}

/* ── Sidebar ── */
.sidebar{
  width:220px;min-height:100vh;background:#18181B;
  display:flex;flex-direction:column;
  position:fixed;left:0;top:0;bottom:0;z-index:200;
  transition:width .25s cubic-bezier(.4,0,.2,1);
  overflow:hidden;
}
.sidebar.collapsed{width:60px;}

.sidebar-header{
  padding:18px 16px;display:flex;align-items:center;
  justify-content:space-between;border-bottom:1px solid rgba(255,255,255,.06);
  min-height:64px;
}
.sidebar-brand{display:flex;align-items:center;gap:10px;overflow:hidden;}
.brand-icon{
  width:32px;height:32px;border-radius:8px;flex-shrink:0;
  background:linear-gradient(135deg,#1e3a5f,#3B82F6);
  display:flex;align-items:center;justify-content:center;
  font-size:16px;color:white;
}
.brand-text{overflow:hidden;white-space:nowrap;}
.brand-name{font-family:'Syne',sans-serif;font-size:16px;font-weight:700;color:#fff;}
.brand-ver{font-size:10px;color:rgba(255,255,255,.3);font-family:'JetBrains Mono',monospace;}

.hamburger{
  width:28px;height:28px;border-radius:6px;background:rgba(255,255,255,.06);
  border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;
  flex-shrink:0;flex-direction:column;gap:4px;padding:6px;
  transition:background .15s;
}
.hamburger:hover{background:rgba(255,255,255,.1);}
.ham-line{height:2px;background:rgba(255,255,255,.6);border-radius:1px;transition:width .2s;}
.ham-line:nth-child(1){width:14px;}
.ham-line:nth-child(2){width:10px;}
.ham-line:nth-child(3){width:14px;}

.sidebar-nav{padding:12px 8px;flex:1;display:flex;flex-direction:column;gap:2px;}

.nav-item{
  display:flex;align-items:center;gap:10px;
  padding:9px 10px;border-radius:8px;cursor:pointer;
  transition:all .15s;color:rgba(255,255,255,.4);
  font-size:13.5px;font-weight:400;border:none;background:none;
  width:100%;text-align:left;white-space:nowrap;overflow:hidden;
  min-height:38px;
}
.nav-item:hover{color:rgba(255,255,255,.75);background:rgba(255,255,255,.05);}
.nav-item.active{background:rgba(59,130,246,.15);color:#60A5FA;font-weight:500;}
.nav-icon-wrap{width:20px;height:20px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:15px;}
.nav-label{overflow:hidden;transition:opacity .2s;}
.sidebar.collapsed .nav-label{opacity:0;}

.sidebar-footer{
  padding:12px 8px;border-top:1px solid rgba(255,255,255,.06);
}
.agent-pill{
  display:flex;align-items:center;gap:8px;
  padding:9px 10px;background:rgba(255,255,255,.04);
  border-radius:8px;overflow:hidden;white-space:nowrap;
}
.agent-dot{width:7px;height:7px;border-radius:50%;background:#22C55E;box-shadow:0 0 6px #22C55E;flex-shrink:0;animation:blink 2s infinite;}
@keyframes blink{0%,100%{opacity:1;}50%{opacity:.4;}}
.agent-txt{font-size:11.5px;color:rgba(255,255,255,.45);overflow:hidden;}
.agent-txt strong{color:#22C55E;font-weight:500;display:block;font-size:12px;}

/* ── Main ── */
.main{margin-left:220px;flex:1;display:flex;flex-direction:column;transition:margin-left .25s cubic-bezier(.4,0,.2,1);}
.main.expanded{margin-left:60px;}

.topbar{
  background:#fff;border-bottom:1px solid #EBEBEB;
  padding:0 28px;height:60px;display:flex;align-items:center;
  justify-content:space-between;position:sticky;top:0;z-index:50;
}
.page-title{font-family:'Syne',sans-serif;font-size:15px;font-weight:700;color:#18181B;}
.page-sub{font-size:11.5px;color:#9CA3AF;margin-top:1px;}
.topbar-r{display:flex;align-items:center;gap:10px;}
.avatar{width:32px;height:32px;border-radius:8px;background:#18181B;display:flex;align-items:center;justify-content:center;color:#fff;font-size:13px;font-weight:600;cursor:pointer;}
.logout-btn{padding:6px 12px;border-radius:7px;background:#F3F4F6;color:#374151;border:none;font-size:12.5px;font-weight:500;cursor:pointer;font-family:'Outfit',sans-serif;transition:background .15s;}
.logout-btn:hover{background:#E5E7EB;}

.content{padding:24px 28px;flex:1;}

/* ── Buttons ── */
.btn{padding:7px 14px;border-radius:7px;font-size:13px;font-weight:500;cursor:pointer;border:none;font-family:'Outfit',sans-serif;transition:all .15s;}
.btn-primary{background:#18181B;color:#fff;}
.btn-primary:hover{background:#2d2d4a;}
.btn-secondary{background:#F3F4F6;color:#374151;}
.btn-secondary:hover{background:#E5E7EB;}
.btn-danger{background:#FEF2F2;color:#DC2626;}
.btn-danger:hover{background:#FEE2E2;}
.btn-sm{padding:5px 10px;font-size:12px;}

/* ── Cards ── */
.card{background:#fff;border:1px solid #EBEBEB;border-radius:12px;overflow:hidden;}
.card-header{padding:16px 20px;border-bottom:1px solid #F3F4F6;display:flex;align-items:center;justify-content:space-between;}
.card-title{font-family:'Syne',sans-serif;font-size:13.5px;font-weight:700;color:#18181B;}
.card-sub{font-size:11.5px;color:#9CA3AF;margin-top:1px;}

/* ── Stat Grid ── */
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px;}
.stat-card{background:#fff;border:1px solid #EBEBEB;border-radius:12px;padding:18px 20px;}
.stat-label{font-size:11px;color:#9CA3AF;font-weight:600;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px;}
.stat-val{font-family:'Syne',sans-serif;font-size:26px;font-weight:700;color:#18181B;letter-spacing:-1px;}
.stat-badge{display:inline-flex;align-items:center;gap:4px;font-size:11px;padding:2px 7px;border-radius:20px;font-weight:500;margin-top:6px;}
.bg-green{background:#F0FDF4;color:#16A34A;}
.bg-red{background:#FEF2F2;color:#DC2626;}
.bg-blue{background:#EFF6FF;color:#2563EB;}
.bg-orange{background:#FFF7ED;color:#EA580C;}
.bg-gray{background:#F3F4F6;color:#6B7280;}

/* ── Table ── */
.table{width:100%;border-collapse:collapse;}
.table th{text-align:left;padding:10px 20px;font-size:10.5px;font-weight:600;color:#9CA3AF;text-transform:uppercase;letter-spacing:.6px;background:#FAFAFA;border-bottom:1px solid #F3F4F6;}
.table td{padding:12px 20px;font-size:13px;color:#374151;border-bottom:1px solid #F9FAFB;}
.table tr:last-child td{border-bottom:none;}
.table tr:hover td{background:#FAFAFA;}
.src-name{font-weight:600;color:#18181B;font-family:'Syne',sans-serif;font-size:13px;}
.src-prod{font-size:11px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:1px;}
.port-tag{display:inline-flex;align-items:center;background:#F3F4F6;color:#374151;padding:3px 8px;border-radius:5px;font-size:11.5px;font-family:'JetBrains Mono',monospace;font-weight:500;}
.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 9px;border-radius:20px;font-size:11.5px;font-weight:500;}
.pill-on{background:#F0FDF4;color:#16A34A;}
.pill-off{background:#F9FAFB;color:#9CA3AF;}
.pdot{width:6px;height:6px;border-radius:50%;}
.pdot-on{background:#22C55E;}
.pdot-off{background:#D1D5DB;}

/* ── Toggle ── */
.toggle{width:34px;height:18px;border-radius:9px;position:relative;cursor:pointer;transition:background .2s;border:none;flex-shrink:0;}
.toggle::after{content:'';position:absolute;width:14px;height:14px;background:white;border-radius:50%;top:2px;left:2px;transition:left .2s;box-shadow:0 1px 3px rgba(0,0,0,.2);}
.toggle.on::after{left:18px;}

/* ── Event feed ── */
.ev-feed{max-height:360px;overflow-y:auto;}
.ev-item{padding:11px 20px;border-bottom:1px solid #F9FAFB;display:flex;gap:10px;align-items:flex-start;}
.ev-item:last-child{border-bottom:none;}
.ev-dot{width:7px;height:7px;border-radius:50%;margin-top:5px;flex-shrink:0;}
.ev-time{font-size:11px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;}
.ev-type{font-size:10px;font-weight:600;padding:1px 5px;border-radius:3px;background:#F3F4F6;color:#6B7280;font-family:'JetBrains Mono',monospace;}
.ev-src{font-size:11px;color:#6B7280;font-weight:500;}
.ev-msg{font-size:12.5px;color:#374151;margin-top:2px;}

/* ── Meter ── */
.meter{height:3px;background:#F3F4F6;border-radius:2px;overflow:hidden;margin-top:5px;}
.meter-fill{height:100%;border-radius:2px;background:linear-gradient(90deg,#3B82F6,#8B5CF6);transition:width .4s;}

/* ── Two col ── */
.two-col{display:grid;grid-template-columns:1fr 320px;gap:16px;}

/* ── Modal ── */
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center;z-index:1000;backdrop-filter:blur(3px);}
.modal{background:#fff;border-radius:14px;width:460px;box-shadow:0 24px 70px rgba(0,0,0,.18);overflow:hidden;}
.modal-hdr{padding:20px 24px 16px;border-bottom:1px solid #F3F4F6;display:flex;align-items:center;justify-content:space-between;}
.modal-title{font-family:'Syne',sans-serif;font-size:15px;font-weight:700;}
.modal-x{width:28px;height:28px;border-radius:6px;border:none;background:#F3F4F6;cursor:pointer;font-size:14px;color:#6B7280;display:flex;align-items:center;justify-content:center;}
.modal-body{padding:20px 24px;display:flex;flex-direction:column;gap:14px;}
.modal-ftr{padding:14px 24px;border-top:1px solid #F3F4F6;display:flex;justify-content:flex-end;gap:8px;}
.fg{display:flex;flex-direction:column;gap:5px;}
.f2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.flabel{font-size:12.5px;font-weight:500;color:#374151;}
.finput{padding:8px 12px;border:1.5px solid #E5E7EB;border-radius:7px;font-size:13px;font-family:'Outfit',sans-serif;color:#18181B;outline:none;transition:border-color .15s;background:#fff;}
.finput:focus{border-color:#3B82F6;box-shadow:0 0 0 3px rgba(59,130,246,.08);}
.fselect{padding:8px 12px;border:1.5px solid #E5E7EB;border-radius:7px;font-size:13px;font-family:'Outfit',sans-serif;color:#18181B;outline:none;background:#fff;cursor:pointer;}

/* ── Parser cards ── */
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

/* ── Destinations ── */
.dest-list{padding:18px;display:flex;flex-direction:column;gap:10px;}
.dcard{border:1px solid #EBEBEB;border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:14px;}
.dicon{width:38px;height:38px;border-radius:9px;background:#F3F4F6;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;}
.dname{font-family:'Syne',sans-serif;font-size:13.5px;font-weight:700;color:#18181B;}
.ddetail{font-size:11.5px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:2px;}

/* ── Settings ── */
.srow{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid #F3F4F6;}
.srow:last-child{border-bottom:none;}
.slabel{font-size:13.5px;font-weight:500;color:#18181B;}
.sdesc{font-size:12px;color:#9CA3AF;margin-top:2px;}

/* ── MAPPER ── */
.mapper-wrap{padding:24px;display:flex;flex-direction:column;gap:20px;}

.mapper-stage{
  display:flex;align-items:stretch;gap:0;
  background:#fff;border:1px solid #EBEBEB;border-radius:14px;
  overflow:hidden;
}

.stage-col{
  flex:1;display:flex;flex-direction:column;
  border-right:1px solid #F3F4F6;
}
.stage-col:last-child{border-right:none;}

.stage-header{
  padding:14px 18px;
  background:#FAFAFA;
  border-bottom:1px solid #F3F4F6;
  display:flex;align-items:center;gap:8px;
}
.stage-icon{
  width:30px;height:30px;border-radius:7px;
  display:flex;align-items:center;justify-content:center;
  font-size:15px;flex-shrink:0;
}
.stage-title{font-family:'Syne',sans-serif;font-size:12.5px;font-weight:700;color:#18181B;}
.stage-sub{font-size:11px;color:#9CA3AF;}

.stage-body{padding:14px;display:flex;flex-direction:column;gap:8px;flex:1;}

.node{
  border-radius:9px;padding:10px 12px;
  display:flex;align-items:center;gap:9px;
  border:1px solid transparent;
  transition:all .2s;position:relative;cursor:default;
}
.node:hover{transform:translateY(-1px);}
.node-ok{background:#F0FDF4;border-color:#BBF7D0;}
.node-warn{background:#FFF7ED;border-color:#FED7AA;}
.node-err{background:#FEF2F2;border-color:#FECACA;}
.node-off{background:#F9FAFB;border-color:#F3F4F6;}

.node-icon{
  width:26px;height:26px;border-radius:6px;
  display:flex;align-items:center;justify-content:center;
  font-size:13px;flex-shrink:0;
}
.node-ok .node-icon{background:#DCFCE7;}
.node-warn .node-icon{background:#FEF3C7;}
.node-err .node-icon{background:#FEE2E2;}
.node-off .node-icon{background:#F3F4F6;}

.node-info{flex:1;min-width:0;}
.node-name{font-size:12.5px;font-weight:600;color:#18181B;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.node-detail{font-size:10.5px;color:#9CA3AF;font-family:'JetBrains Mono',monospace;margin-top:1px;}

.node-status{
  width:8px;height:8px;border-radius:50%;flex-shrink:0;
}
.ns-ok{background:#22C55E;box-shadow:0 0 5px #22C55E;}
.ns-warn{background:#F59E0B;box-shadow:0 0 5px #F59E0B;}
.ns-err{background:#EF4444;box-shadow:0 0 5px #EF4444;}
.ns-off{background:#D1D5DB;}

.node-err-badge{
  position:absolute;top:-4px;right:-4px;
  width:16px;height:16px;background:#EF4444;
  border-radius:50%;color:white;font-size:9px;font-weight:700;
  display:flex;align-items:center;justify-content:center;
  border:2px solid white;
}

/* Flow arrows between stages */
.stage-arrow{
  width:32px;display:flex;align-items:center;justify-content:center;
  flex-shrink:0;color:#D1D5DB;font-size:16px;
  background:#fff;z-index:1;
}

/* Mapper summary bar */
.mapper-summary{
  display:grid;grid-template-columns:repeat(4,1fr);gap:12px;
}
.sum-card{
  background:#fff;border:1px solid #EBEBEB;border-radius:10px;
  padding:14px 16px;display:flex;align-items:center;gap:12px;
}
.sum-icon{
  width:36px;height:36px;border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:17px;flex-shrink:0;
}
.sum-label{font-size:11px;color:#9CA3AF;font-weight:500;text-transform:uppercase;letter-spacing:.5px;}
.sum-val{font-family:'Syne',sans-serif;font-size:20px;font-weight:700;color:#18181B;line-height:1;}

/* Legend */
.legend{display:flex;align-items:center;gap:16px;padding:0 4px;}
.leg-item{display:flex;align-items:center;gap:5px;font-size:11.5px;color:#6B7280;}
.leg-dot{width:8px;height:8px;border-radius:50%;}

::-webkit-scrollbar{width:4px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:#E5E7EB;border-radius:2px;}
`;

// ── Login ──────────────────────────────────────────────────────────────────
function Login({ onLogin }) {
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!user || !pass) { setErr("Please enter username and password."); return; }
    setLoading(true); setErr("");
    try {
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: user, password: pass })
      });
      if (res.ok) {
        const data = await res.json();
        localStorage.setItem("sb_token", data.token);
        onLogin(user);
      } else {
        setErr("Invalid credentials.");
        setLoading(false);
      }
    } catch {
      if (user === "admin" && pass === "admin") { onLogin(user); }
      else { setErr("Invalid credentials. (Demo: admin / admin)"); setLoading(false); }
    }
  };

  return (
    <div className="login-wrap">
      <div className="login-bg-grid"/>
      <div className="login-glow"/>
      <div className="login-card">
        <div className="login-logo">
          <div className="login-logo-icon">⬡</div>
          <div>
            <div className="login-logo-name">SecBridge</div>
            <div className="login-logo-ver">v3.1 — Security Log Router</div>
          </div>
        </div>
        <div className="login-title">Welcome back</div>
        <div className="login-sub">Sign in to your SecBridge dashboard</div>
        {err && <div className="login-err">{err}</div>}
        <div className="login-field">
          <label className="login-label">Username</label>
          <input className="login-input" placeholder="admin" value={user}
            onChange={e=>setUser(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&submit()}/>
        </div>
        <div className="login-field">
          <label className="login-label">Password</label>
          <input className="login-input" type="password" placeholder="••••••••" value={pass}
            onChange={e=>setPass(e.target.value)}
            onKeyDown={e=>e.key==="Enter"&&submit()}/>
        </div>
        <button className="login-btn" onClick={submit} disabled={loading}>
          {loading ? "Signing in…" : "Sign In →"}
        </button>
        <div className="login-footer">Demo credentials: admin / admin</div>
      </div>
    </div>
  );
}

// ── Mapper ─────────────────────────────────────────────────────────────────
function Mapper({ sources }) {
  const activeCount  = sources.filter(s=>s.status==="active").length;
  const warnCount    = sources.filter(s=>s.status==="active"&&s.errors>0).length;
  const errCount     = sources.filter(s=>s.status==="inactive").length;
  const totalLogs    = sources.reduce((a,s)=>a+s.logsPerMin,0);

  const destStatus = "ok";
  const agentStatus = "ok";

  const getNodeClass = (s) => {
    if (s.status === "inactive") return "node-off";
    if (s.errors > 0) return "node-warn";
    return "node-ok";
  };
  const getNsClass = (s) => {
    if (s.status === "inactive") return "ns-off";
    if (s.errors > 0) return "ns-warn";
    return "ns-ok";
  };

  return (
    <div className="mapper-wrap">
      {/* Summary */}
      <div className="mapper-summary">
        {[
          { icon:"📡", bg:"#EFF6FF", label:"Total Sources", val:sources.length },
          { icon:"✅", bg:"#F0FDF4", label:"Healthy", val:activeCount - warnCount },
          { icon:"⚠️", bg:"#FFFBEB", label:"Warnings", val:warnCount },
          { icon:"📊", bg:"#F5F3FF", label:"Logs / min", val:totalLogs },
        ].map((s,i)=>(
          <div className="sum-card" key={i}>
            <div className="sum-icon" style={{background:s.bg}}>{s.icon}</div>
            <div>
              <div className="sum-label">{s.label}</div>
              <div className="sum-val">{s.val}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Legend */}
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <div style={{fontFamily:"'Syne',sans-serif",fontSize:13,fontWeight:700,color:"#18181B"}}>
          Pipeline Flow
        </div>
        <div className="legend">
          {[
            {color:"#22C55E",label:"Healthy"},
            {color:"#F59E0B",label:"Warning"},
            {color:"#EF4444",label:"Error / Offline"},
            {color:"#D1D5DB",label:"Inactive"},
          ].map((l,i)=>(
            <div className="leg-item" key={i}>
              <div className="leg-dot" style={{background:l.color}}/>
              {l.label}
            </div>
          ))}
        </div>
      </div>

      {/* Pipeline */}
      <div className="mapper-stage">
        {/* Col 1: Sources */}
        <div className="stage-col">
          <div className="stage-header">
            <div className="stage-icon" style={{background:"#EFF6FF"}}>📡</div>
            <div>
              <div className="stage-title">Sources</div>
              <div className="stage-sub">Syslog devices</div>
            </div>
          </div>
          <div className="stage-body">
            {sources.map(s=>(
              <div className={`node ${getNodeClass(s)}`} key={s.id}>
                {s.errors > 0 && <div className="node-err-badge">{s.errors}</div>}
                <div className="node-icon">🔥</div>
                <div className="node-info">
                  <div className="node-name">{s.name}</div>
                  <div className="node-detail">:{s.port}/{s.protocol} · {s.logsPerMin} logs/min</div>
                </div>
                <div className={`node-status ${getNsClass(s)}`}/>
              </div>
            ))}
          </div>
        </div>

        <div className="stage-arrow">→</div>

        {/* Col 2: SecBridge Receiver */}
        <div className="stage-col">
          <div className="stage-header">
            <div className="stage-icon" style={{background:"#F5F3FF"}}>⬡</div>
            <div>
              <div className="stage-title">SecBridge</div>
              <div className="stage-sub">Syslog receiver</div>
            </div>
          </div>
          <div className="stage-body" style={{justifyContent:"center"}}>
            <div className="node node-ok">
              <div className="node-icon">⚡</div>
              <div className="node-info">
                <div className="node-name">Scalyr Agent 2</div>
                <div className="node-detail">scalyr-agent-2 · running</div>
              </div>
              <div className="node-status ns-ok"/>
            </div>
            <div className="node node-ok" style={{marginTop:4}}>
              <div className="node-icon">📂</div>
              <div className="node-info">
                <div className="node-name">Log Router</div>
                <div className="node-detail">{sources.filter(s=>s.status==="active").length} active routes</div>
              </div>
              <div className="node-status ns-ok"/>
            </div>
          </div>
        </div>

        <div className="stage-arrow">→</div>

        {/* Col 3: Parsers */}
        <div className="stage-col">
          <div className="stage-header">
            <div className="stage-icon" style={{background:"#FFF7ED"}}>◈</div>
            <div>
              <div className="stage-title">Parsers</div>
              <div className="stage-sub">Optional · or SDL</div>
            </div>
          </div>
          <div className="stage-body">
            {sources.map(s=>{
              const hasParser = s.parser !== "none";
              return (
                <div className={`node ${hasParser&&s.status==="active"?"node-ok":"node-off"}`} key={s.id}>
                  <div className="node-icon">{hasParser?"🔧":"—"}</div>
                  <div className="node-info">
                    <div className="node-name" style={{color:hasParser?"#18181B":"#9CA3AF"}}>
                      {hasParser ? s.parser : "no parser"}
                    </div>
                    <div className="node-detail">{hasParser?"local parse":"SDL handles"}</div>
                  </div>
                  <div className={`node-status ${hasParser&&s.status==="active"?"ns-ok":"ns-off"}`}/>
                </div>
              );
            })}
          </div>
        </div>

        <div className="stage-arrow">→</div>

        {/* Col 4: Log Files */}
        <div className="stage-col">
          <div className="stage-header">
            <div className="stage-icon" style={{background:"#F0FDF4"}}>📁</div>
            <div>
              <div className="stage-title">Log Files</div>
              <div className="stage-sub">/var/log/scalyr-agent-2</div>
            </div>
          </div>
          <div className="stage-body">
            {sources.map(s=>(
              <div className={`node ${s.status==="active"?"node-ok":"node-off"}`} key={s.id}>
                <div className="node-icon">📄</div>
                <div className="node-info">
                  <div className="node-name">{s.product}.log</div>
                  <div className="node-detail">{s.status==="active"?"writing":"idle"}</div>
                </div>
                <div className={`node-status ${s.status==="active"?"ns-ok":"ns-off"}`}/>
              </div>
            ))}
          </div>
        </div>

        <div className="stage-arrow">→</div>

        {/* Col 5: Destination */}
        <div className="stage-col">
          <div className="stage-header">
            <div className="stage-icon" style={{background:"#EFF6FF"}}>⤴</div>
            <div>
              <div className="stage-title">Destination</div>
              <div className="stage-sub">SentinelOne SDL</div>
            </div>
          </div>
          <div className="stage-body" style={{justifyContent:"center"}}>
            <div className="node node-ok">
              <div className="node-icon">🛡️</div>
              <div className="node-info">
                <div className="node-name">SentinelOne SDL</div>
                <div className="node-detail">xdr.us1.sentinelone.net</div>
              </div>
              <div className="node-status ns-ok"/>
            </div>
            <div className="node node-ok" style={{marginTop:4}}>
              <div className="node-icon">🔍</div>
              <div className="node-info">
                <div className="node-name">SDL Parser</div>
                <div className="node-detail">field extraction</div>
              </div>
              <div className="node-status ns-ok"/>
            </div>
            <div className="node node-ok" style={{marginTop:4}}>
              <div className="node-icon">⚡</div>
              <div className="node-info">
                <div className="node-name">STAR Rules</div>
                <div className="node-detail">alert triggers</div>
              </div>
              <div className="node-status ns-ok"/>
            </div>
          </div>
        </div>
      </div>

      {/* Warning callouts */}
      {sources.filter(s=>s.errors>0).map(s=>(
        <div key={s.id} style={{
          background:"#FFFBEB",border:"1px solid #FED7AA",borderRadius:10,
          padding:"12px 16px",display:"flex",alignItems:"center",gap:10
        }}>
          <span style={{fontSize:16}}>⚠️</span>
          <div>
            <div style={{fontSize:13,fontWeight:600,color:"#92400E"}}>{s.name} — {s.errors} parse error{s.errors>1?"s":""}</div>
            <div style={{fontSize:12,color:"#B45309",marginTop:2}}>
              Check parser rules in SDL console or review /var/log/scalyr-agent-2/{s.product}.log
            </div>
          </div>
        </div>
      ))}
      {sources.filter(s=>s.status==="inactive").map(s=>(
        <div key={s.id} style={{
          background:"#F9FAFB",border:"1px solid #E5E7EB",borderRadius:10,
          padding:"12px 16px",display:"flex",alignItems:"center",gap:10
        }}>
          <span style={{fontSize:16}}>⭕</span>
          <div>
            <div style={{fontSize:13,fontWeight:600,color:"#374151"}}>{s.name} — inactive</div>
            <div style={{fontSize:12,color:"#9CA3AF",marginTop:2}}>
              No logs received on port {s.port}. Check device syslog config points to this collector.
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Dashboard ──────────────────────────────────────────────────────────────
function Dashboard({ sources }) {
  const [tick, setTick] = useState(0);
  useEffect(()=>{ const t=setInterval(()=>setTick(v=>v+1),2000); return ()=>clearInterval(t); },[]);
  const active = sources.filter(s=>s.status==="active").length;
  const total  = sources.reduce((a,s)=>a+s.logsPerMin,0);
  const crit   = MOCK_EVENTS.filter(e=>e.severity==="critical").length;

  return (
    <div>
      <div className="stat-grid">
        {[
          { label:"Active Sources", val:`${active}/${sources.length}`, badge:"● "+active+" online", bc:"bg-green" },
          { label:"Logs / Min", val:total+(tick%3===0?4:tick%2===0?-2:1), badge:"↑ live", bc:"bg-blue" },
          { label:"Critical Events", val:crit, badge:"last 1h", bc:"bg-red", vc:"#DC2626" },
          { label:"Agent Status", val:"Running", badge:"● scalyr-agent-2", bc:"bg-green", vs:16 },
        ].map((s,i)=>(
          <div className="stat-card" key={i}>
            <div className="stat-label">{s.label}</div>
            <div className="stat-val" style={{color:s.vc||"#18181B",fontSize:s.vs}}>{s.val}</div>
            <span className={`stat-badge ${s.bc}`}>{s.badge}</span>
          </div>
        ))}
      </div>
      <div className="two-col">
        <div className="card">
          <div className="card-header">
            <div><div className="card-title">Sources</div><div className="card-sub">Live throughput</div></div>
          </div>
          <table className="table">
            <thead><tr><th>Source</th><th>Port</th><th>Status</th><th>Logs/min</th><th>Last seen</th></tr></thead>
            <tbody>
              {sources.map(s=>(
                <tr key={s.id}>
                  <td><div className="src-name">{s.name}</div><div className="src-prod">{s.product}</div></td>
                  <td><span className="port-tag">{s.port}/{s.protocol}</span></td>
                  <td><span className={`pill ${s.status==="active"?"pill-on":"pill-off"}`}><span className={`pdot ${s.status==="active"?"pdot-on":"pdot-off"}`}/>{s.status}</span></td>
                  <td>
                    <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:13}}>{s.logsPerMin}</div>
                    <div className="meter"><div className="meter-fill" style={{width:`${Math.min(100,(s.logsPerMin/200)*100)}%`}}/></div>
                  </td>
                  <td style={{fontSize:12,color:"#9CA3AF"}}>{s.lastSeen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-header"><div className="card-title">Recent Events</div><span className="stat-badge bg-blue">{MOCK_EVENTS.length} today</span></div>
          <div className="ev-feed">
            {MOCK_EVENTS.map((e,i)=>{
              const s=SEV[e.severity];
              return (
                <div className="ev-item" key={i}>
                  <div className="ev-dot" style={{background:s.dot}}/>
                  <div>
                    <div style={{display:"flex",gap:5,alignItems:"center",marginBottom:2}}>
                      <span className="ev-time">{e.time}</span>
                      <span className="ev-type">{e.type}</span>
                      <span className="ev-src">{e.source.split(" ")[0]}</span>
                    </div>
                    <div className="ev-msg">{e.msg}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Sources Page ───────────────────────────────────────────────────────────
function Sources({ sources, setSources }) {
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({name:"",product:"",port:"",protocol:"udp",allowed_ips:""});

  const toggle = async id => {
    try {
      await fetch(`${API}/sources/${id}/toggle`, { method:"PATCH", headers:authHeaders() });
    } catch {}
    setSources(p=>p.map(s=>s.id===id?{...s,status:s.status==="active"?"inactive":"active"}:s));
  };

  const remove = async id => {
    try {
      await fetch(`${API}/sources/${id}`, { method:"DELETE", headers:authHeaders() });
    } catch {}
    setSources(p=>p.filter(s=>s.id!==id));
  };

  const add = async () => {
    if(!form.name||!form.port) return;
    try {
      const res = await fetch(`${API}/sources`, {
        method:"POST", headers:authHeaders(),
        body: JSON.stringify({
          name: form.name,
          product: form.product || form.name.toLowerCase().replace(/\s+/g,"-"),
          syslog_port: parseInt(form.port),
          protocol: form.protocol,
          allowed_ips: form.allowed_ips ? [form.allowed_ips] : [],
        })
      });
      if (res.ok) {
        const data = await res.json();
        setSources(p=>[...p, data.source]);
      }
    } catch {
      setSources(p=>[...p,{
        id:String(p.length+1).padStart(3,"0"),name:form.name,
        product:form.product||form.name.toLowerCase().replace(/\s+/g,"-"),
        port:parseInt(form.port),protocol:form.protocol.toUpperCase(),
        status:"active",logsPerMin:0,allowed_ips:form.allowed_ips?[form.allowed_ips]:[],
        lastSeen:"never",parser:"none",errors:0
      }]);
    }
    setForm({name:"",product:"",port:"",protocol:"udp",allowed_ips:""});
    setShowAdd(false);
  };

  return (
    <div>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">Syslog Sources</div><div className="card-sub">{sources.length} configured · {sources.filter(s=>s.status==="active").length} active</div></div>
          <button className="btn btn-primary" onClick={()=>setShowAdd(true)}>+ Add Source</button>
        </div>
        <table className="table">
          <thead><tr><th>Source</th><th>Port / Proto</th><th>Allowed IPs</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody>
            {sources.map(s=>(
              <tr key={s.id}>
                <td><div className="src-name">{s.name}</div><div className="src-prod">ID:{s.id} · {s.product}</div></td>
                <td><span className="port-tag">{s.port}/{s.protocol}</span></td>
                <td style={{fontSize:12,fontFamily:"'JetBrains Mono',monospace",color:"#6B7280"}}>{s.allowed_ips.length?s.allowed_ips.join(", "):<span style={{color:"#D1D5DB"}}>any</span>}</td>
                <td><span className={`pill ${s.status==="active"?"pill-on":"pill-off"}`}><span className={`pdot ${s.status==="active"?"pdot-on":"pdot-off"}`}/>{s.status}</span></td>
                <td><div style={{display:"flex",alignItems:"center",gap:8}}>
                  <button className="toggle" style={{background:s.status==="active"?"#22C55E":"#D1D5DB"}} onClick={()=>toggle(s.id)}/>
                  <button className="btn btn-danger btn-sm" onClick={()=>remove(s.id)}>Remove</button>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {showAdd && (
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
            </div>
            <div className="modal-ftr"><button className="btn btn-secondary" onClick={()=>setShowAdd(false)}>Cancel</button><button className="btn btn-primary" onClick={add}>Add Source</button></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Parsers Page ───────────────────────────────────────────────────────────
function Parsers() {
  const [parsers,setParsers] = useState(MOCK_PARSERS);
  const toggle = id => setParsers(p=>p.map(x=>x.id===id?{...x,status:x.status==="active"?"inactive":"active"}:x));
  return (
    <div className="card">
      <div className="card-header">
        <div><div className="card-title">Parser Library</div><div className="card-sub">Optional — SDL can handle parsing directly</div></div>
        <button className="btn btn-primary">↑ Upload</button>
      </div>
      <div className="parser-grid">
        {parsers.map(p=>(
          <div className="pcard" key={p.id}>
            <div className="pcard-hdr">
              <div><div className="pname">{p.name}</div><div className="pvendor">{p.vendor}</div></div>
              <button className="toggle" style={{background:p.status==="active"?"#22C55E":"#D1D5DB"}} onClick={()=>toggle(p.id)}/>
            </div>
            <div className="pmeta">
              <span className="stat-badge bg-blue">{p.format}</span>
              <span className="stat-badge bg-green">{p.fields} fields</span>
            </div>
            <div className="pfile">{p.file}</div>
          </div>
        ))}
        <div className="pcard-add" onClick={()=>{}}>
          <div style={{textAlign:"center",color:"#9CA3AF"}}>
            <div style={{fontSize:22,marginBottom:4}}>+</div>
            <div style={{fontSize:12}}>Add parser</div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Destinations Page ──────────────────────────────────────────────────────
function Destinations() {
  const [key,setKey]=useState("sk-••••••••••••••••••••••");
  const [url,setUrl]=useState("https://xdr.us1.sentinelone.net");
  const [tested,setTested]=useState(null);
  const test=()=>{setTested("testing");setTimeout(()=>setTested("success"),1400);};
  return (
    <div style={{display:"flex",flexDirection:"column",gap:14}}>
      <div className="card">
        <div className="card-header">
          <div><div className="card-title">SentinelOne SDL</div><div className="card-sub">Primary destination</div></div>
          <span className="pill pill-on"><span className="pdot pdot-on"/>connected</span>
        </div>
        <div className="dest-list">
          <div className="fg"><label className="flabel">Write API Key</label><input className="finput" value={key} onChange={e=>setKey(e.target.value)} style={{fontFamily:"'JetBrains Mono',monospace"}}/></div>
          <div className="fg"><label className="flabel">Ingest URL</label><input className="finput" value={url} onChange={e=>setUrl(e.target.value)} style={{fontFamily:"'JetBrains Mono',monospace"}}/></div>
          <div style={{display:"flex",gap:8}}>
            <button className="btn btn-secondary" onClick={test}>{tested==="testing"?"⏳ Testing…":tested==="success"?"✓ OK":"Test Connection"}</button>
            <button className="btn btn-primary">Save</button>
          </div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Other Destinations</div><div className="card-sub">Coming in v4</div></div>
        <div className="dest-list">
          {[["📊","Splunk","HTTP Event Collector"],["🔍","Elastic SIEM","Elasticsearch"],["📁","CSV Export","Local file"],["🔗","Webhook","HTTP endpoint"]].map(([icon,name,detail],i)=>(
            <div className="dcard" key={i} style={{opacity:.55}}>
              <div className="dicon">{icon}</div>
              <div><div className="dname">{name}</div><div className="ddetail">{detail}</div></div>
              <span className="stat-badge bg-orange" style={{marginLeft:"auto"}}>v4</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Settings Page ──────────────────────────────────────────────────────────
function Settings() {
  const [auto,setAuto]=useState(true);
  const [rot,setRot]=useState(true);
  return (
    <div style={{display:"flex",flexDirection:"column",gap:14}}>
      <div className="card">
        <div className="card-header"><div className="card-title">System</div></div>
        <div style={{padding:"0 20px"}}>
          {[
            {l:"Agent Auto-restart",d:"Restart on failure",v:auto,s:setAuto},
            {l:"Log Rotation",d:"20MB limit, 5 backups",v:rot,s:setRot},
          ].map((r,i)=>(
            <div className="srow" key={i}>
              <div><div className="slabel">{r.l}</div><div className="sdesc">{r.d}</div></div>
              <button className="toggle" style={{background:r.v?"#22C55E":"#D1D5DB"}} onClick={()=>r.s(v=>!v)}/>
            </div>
          ))}
          <div className="srow">
            <div><div className="slabel">Restart Agent</div><div className="sdesc">Apply changes</div></div>
            <button className="btn btn-secondary btn-sm">Restart</button>
          </div>
          <div className="srow">
            <div><div className="slabel">Version</div><div className="sdesc">Current release</div></div>
            <span className="stat-badge bg-blue" style={{fontFamily:"'JetBrains Mono',monospace"}}>v3.1</span>
          </div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><div className="card-title">Config Files</div></div>
        <div style={{padding:"0 20px"}}>
          {[
            {l:"sources.json",p:"/opt/secbridge/config/sources.json"},
            {l:"agent.json",p:"/etc/scalyr-agent-2/agent.json"},
            {l:"Install log",p:"/var/log/sangfor-s1-install.log"},
          ].map((f,i)=>(
            <div className="srow" key={i}>
              <div><div className="slabel">{f.l}</div><div className="sdesc" style={{fontFamily:"'JetBrains Mono',monospace"}}>{f.p}</div></div>
              <button className="btn btn-secondary btn-sm">View</button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Nav items ──────────────────────────────────────────────────────────────
const NAV = [
  {id:"dashboard", label:"Dashboard",    icon:"⬡"},
  {id:"mapper",    label:"Pipeline Map", icon:"◈"},
  {id:"sources",   label:"Sources",      icon:"⇄"},
  {id:"parsers",   label:"Parsers",      icon:"⚙"},
  {id:"destinations",label:"Destinations",icon:"⤴"},
  {id:"settings",  label:"Settings",     icon:"≡"},
];

const TITLES = {
  dashboard:    {t:"Dashboard",       s:"Live overview"},
  mapper:       {t:"Pipeline Map",    s:"End-to-end flow status — see exactly where issues are"},
  sources:      {t:"Sources",         s:"Manage syslog sources"},
  parsers:      {t:"Parsers",         s:"Vendor log format parsers"},
  destinations: {t:"Destinations",    s:"Where logs go after collection"},
  settings:     {t:"Settings",        s:"System configuration"},
};

// ── App ────────────────────────────────────────────────────────────────────
export default function App() {
  const [authed, setAuthed]       = useState(false);
  const [user, setUser]           = useState("");
  const [token, setToken]         = useState(localStorage.getItem("sb_token") || "");
  const [page, setPage]           = useState("dashboard");
  const [collapsed, setCollapsed] = useState(false);
  const [sources, setSources]     = useState([]);

  const authHeaders = () => ({ "Authorization": `Bearer ${token}`, "Content-Type": "application/json" });

  const loadSources = useCallback(async () => {
    try {
      const res = await fetch(`${API}/sources`, { headers: authHeaders() });
      if (res.ok) { setSources(await res.json()); }
      else { setSources(MOCK_SOURCES); }
    } catch { setSources(MOCK_SOURCES); }
  }, [token]);

  useEffect(() => { if (authed) loadSources(); }, [authed]);
  useEffect(() => { if (authed) { const t = setInterval(loadSources, 10000); return () => clearInterval(t); } }, [authed]);

  const handleLogin = (u, tok) => {
    setUser(u);
    if (tok) { setToken(tok); localStorage.setItem("sb_token", tok); }
    setAuthed(true);
  };

  const handleLogout = async () => {
    try { await fetch(`${API}/logout`, { method:"POST", headers:authHeaders() }); } catch {}
    localStorage.removeItem("sb_token");
    setAuthed(false); setToken("");
  };

  if (!authed) return (
    <>
      <style>{CSS}</style>
      <Login onLogin={handleLogin}/>
    </>
  );

  const cur = TITLES[page];

  return (
    <>
      <style>{CSS}</style>
      <div className="shell">
        {/* Sidebar */}
        <aside className={`sidebar ${collapsed?"collapsed":""}`}>
          <div className="sidebar-header">
            <div className="sidebar-brand">
              <div className="brand-icon">⬡</div>
              <div className="brand-text">
                <div className="brand-name">SecBridge</div>
                <div className="brand-ver">v3.1</div>
              </div>
            </div>
            <button className="hamburger" onClick={()=>setCollapsed(v=>!v)} title="Toggle sidebar">
              <div className="ham-line"/>
              <div className="ham-line"/>
              <div className="ham-line"/>
            </button>
          </div>

          <nav className="sidebar-nav">
            {NAV.map(item=>(
              <button key={item.id}
                className={`nav-item ${page===item.id?"active":""}`}
                onClick={()=>setPage(item.id)}
                title={collapsed?item.label:""}
              >
                <div className="nav-icon-wrap">{item.icon}</div>
                <span className="nav-label">{item.label}</span>
              </button>
            ))}
          </nav>

          <div className="sidebar-footer">
            <div className="agent-pill">
              <div className="agent-dot"/>
              <div className="agent-txt">
                <strong>Agent running</strong>
                scalyr-agent-2
              </div>
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className={`main ${collapsed?"expanded":""}`}>
          <div className="topbar">
            <div>
              <div className="page-title">{cur.t}</div>
              <div className="page-sub">{cur.s}</div>
            </div>
            <div className="topbar-r">
              <button className="logout-btn" onClick={handleLogout}>Sign out</button>
              <div className="avatar">{user[0]?.toUpperCase()}</div>
            </div>
          </div>

          <div className="content">
            {page==="dashboard"    && <Dashboard sources={sources}/>}
            {page==="mapper"       && <Mapper sources={sources}/>}
            {page==="sources"      && <Sources sources={sources} setSources={setSources}/>}
            {page==="parsers"      && <Parsers/>}
            {page==="destinations" && <Destinations/>}
            {page==="settings"     && <Settings/>}
          </div>
        </main>
      </div>
    </>
  );
}
