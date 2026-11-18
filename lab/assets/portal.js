/* ==========================================================================
   Meridian Freight — Employee Portal
   Shared data + client-side session handling.

   Sequential employee IDs and secrets left sitting in a free-text "notes"
   field are the flaws this portal is built around. The whole directory ships
   to the browser because there is no backend — treat anything here as public.
   ========================================================================== */

var EMPLOYEES = {
  1000:{name:"Dana Okonkwo", role:"System Administrator", admin:true,
        email:"dana.okonkwo@meridianfreight.co", dept:"IT Operations", ext:"x1000",
        notes:"Password reset 2024-11-14 (ticket #4471). Temporary admin credential set to "+
              "M3ridian-Adm!n — user MUST rotate before the Q1 access audit."},
  1017:{name:"Priya Raman", role:"Logistics Coordinator",
        email:"priya.raman@meridianfreight.co", dept:"Operations", ext:"x1017"},
  1023:{name:"Marcus Feld", role:"Accounts Payable",
        email:"marcus.feld@meridianfreight.co", dept:"Finance", ext:"x1023",
        notes:"Vendor ACH details for Route-9 Fuel stored under Finance share — do not distribute."},
  1031:{name:"Tomas Alvarez", role:"Fleet Manager",
        email:"tomas.alvarez@meridianfreight.co", dept:"Operations", ext:"x1031"},
  1042:{name:"Guest (Temporary Access)", role:"Onboarding — Unprovisioned", you:true,
        email:"temp-access@meridianfreight.co", dept:"—", ext:"—"},
  1048:{name:"Sarah Chen", role:"HR Generalist",
        email:"sarah.chen@meridianfreight.co", dept:"People", ext:"x1048",
        notes:"Comp band review spreadsheet (all staff salaries) shared to my drive this week."}
};

/* Accounts the portal accepts. A temporary guest account that was never
   disabled, and an administrator whose reset password was never rotated. */
var ACCOUNTS = {
  "guest":         {pass:"guest",          role:"guest", id:1042, display:"guest"},
  "dana.okonkwo":  {pass:"M3ridian-Adm!n", role:"admin", id:1000, display:"Dana Okonkwo"}
};

/* ---- session (per browser tab) ---- */
var SESSION_KEY = "mf_session";

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

/* Render the signed-in identity + sign-out control into a .topbar-user slot. */
function renderUserBar(session){
  var el = document.querySelector(".topbar-user");
  if(!el) return;
  if(!session){ el.innerHTML = ""; return; }
  var label = session.role === "admin"
    ? "<b>" + session.display + "</b> · Administrator"
    : "<b>" + session.display + "</b> · Temporary access";
  el.innerHTML = label + '<br><a class="signout" href="#" data-signout>Sign out</a>';
  var link = el.querySelector("[data-signout]");
  link.addEventListener("click", function(e){
    e.preventDefault();
    clearSession();
    location.href = "../login/";
  });
}
