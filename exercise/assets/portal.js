/* ==========================================================================
   Verdant Retail Group — IT Service Desk
   Shared data + client-side session handling.

   Support tickets are keyed by a short, sequential reference. The ticket view
   trusts that reference straight from the URL, and some of these tickets carry
   things that were never meant to leave the person who filed them.
   ========================================================================== */

/* Accounts the portal accepts. */
var ACCOUNTS = {
  "helpdesk.intern":{pass:"Welcome2024!",  role:"agent", user:"helpdesk.intern", display:"Sam Rivera"},
  "sysadmin":       {pass:"Sup3rv!sor#22", role:"admin", user:"sysadmin",        display:"IT Administrator"}
};

/* The support queue. `assignee` is who the ticket belongs to — the "My tickets"
   list respects it, but opening a ticket by reference does not. */
var TICKETS = {
  10413:{subject:"Second monitor flickering at till 3",
         requester:"Dana Whitfield · Store Operations", assignee:"t.brooks",
         status:"open", priority:"normal", opened:"2026-09-21",
         body:"The second display at till 3 flickers every few minutes since the weekend. "+
              "Tried a different cable, no change. Can someone swap the monitor?"},

  10414:{subject:"Refund not received — order #88231",
         requester:"customer relay · web form", assignee:"t.brooks",
         status:"pending", priority:"high", opened:"2026-09-22",
         body:"Forwarded from the store inbox.\n\n"+
              "Customer: Helen Marsh, 14 Oakfield Road, Redhill RH1 2LP\n"+
              "Order #88231 — charged twice (card ending 4471), £129.99 each.\n"+
              "One charge needs reversing. Customer has called twice, please prioritise."},

  10415:{subject:"Reset my login for the rota system",
         requester:"Sam Rivera · Service Desk", assignee:"helpdesk.intern",
         status:"open", priority:"normal", opened:"2026-09-26",
         body:"My rota-system password expired and the self-service reset link "+
              "just loops back to the login page. Can you push a reset from your side?"},

  10416:{subject:"New-starter laptop — warehouse pick team",
         requester:"People Team · onboarding", assignee:"helpdesk.intern",
         status:"open", priority:"normal", opened:"2026-09-28",
         body:"New picker starts Monday. Standard warehouse image, no admin rights, "+
              "needs the scanner app and a locker code. Desk collection is fine."},

  10417:{subject:"Payroll export for the Q2 audit",
         requester:"Finance · J. Okafor", assignee:"j.patel",
         status:"closed", priority:"normal", opened:"2026-09-18",
         body:"For the audit I've dropped the full Q2 payroll export (every employee, "+
              "base + bonus) onto the shared Finance drive, folder \"Audit-Q2\". "+
              "Link is open to anyone in the company — please don't circulate it wider."},

  10418:{subject:"[Internal] Service Desk admin account reset",
         requester:"IT · sysadmin", assignee:"j.patel",
         status:"open", priority:"high", internal:true, opened:"2026-09-27",
         body:"Migration housekeeping for whoever picks this up on-call.",
         note:"I've reset the Service Desk admin login as part of the portal migration.\n"+
              "Sign in with  sysadmin / Sup3rv!sor#22  to finish the queue "+
              "configuration. Rotate the password once the migration is signed off — "+
              "leaving it here so the on-call agent isn't blocked over the weekend."}
};

/* ---- session (per browser tab) ---- */
var SESSION_KEY = "vrg_session";

function getSession(){
  try{ return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null"); }
  catch(e){ return null; }
}
function setSession(s){
  try{ sessionStorage.setItem(SESSION_KEY, JSON.stringify(s)); }catch(e){}
}
function clearSession(){
  try{ sessionStorage.removeItem(SESSION_KEY); }catch(e){}
}

function escapeHtml(s){
  return String(s).replace(/[&<>"]/g, function(c){
    return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];
  });
}

/* Render the signed-in identity + sign-out control into a .topbar-user slot. */
function renderUserBar(session){
  var el = document.querySelector(".topbar-user");
  if(!el) return;
  if(!session){ el.innerHTML = ""; return; }
  var label = session.role === "admin"
    ? "<b>" + escapeHtml(session.display) + "</b> · Administrator"
    : "<b>" + escapeHtml(session.display) + "</b> · Support agent";
  el.innerHTML = label + '<br><a class="signout" href="#" data-signout>Sign out</a>';
  el.querySelector("[data-signout]").addEventListener("click", function(e){
    e.preventDefault();
    clearSession();
    location.href = "../login/";
  });
}
