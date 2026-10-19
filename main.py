# -*- coding:UTF-8 -*-
__author__ = "Victor de Queiroz & Erik Tonon"
"""
             ██████  ██▓███   ▒█████  
           ▒██    ▒ ▓██░  ██▒▒██▒  ██▒
           ░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒
             ▒   ██▒▒██▄█▓▒ ▒▒██   ██░
           ▒██████▒▒▒██▒ ░  ░░ ████▓▒░
           ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ 
           ░ ░▒  ░ ░░▒ ░       ░ ▒ ▒░ 
           ░  ░  ░  ░░       ░ ░ ░ ▒  
                 ░               ░ ░

        S n e a k    P e e k   O S I N T  v2.0 (2026 Edition)

SPO is an open-source intelligence (OSINT) reconnaissance platform for
Security Researchers, Pentesters, Threat Analysts, Lawyers, HR, and Journalists.
Licensed under GPLv2.
"""
import os
import secrets
from datetime import timedelta
from functools import wraps
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from controller import (
    CNPJ,
    Facebook,
    Jurisprudence,
    Shodan,
    Subdomain,
    VirusTotal,
    Whois,
    spoDAO,
)

spo = Flask(__name__, template_folder="templates", static_folder="static")
spo.secret_key = os.environ.get("SPO_SECRET_KEY") or secrets.token_hex(32)
spo.permanent_session_lifetime = timedelta(minutes=60)

# Controllers & DAO instances
dao = spoDAO.SpoDAO()
whois_ctrl = Whois.Whois()
cnpj_ctrl = CNPJ.CNPJ()
lawyer_ctrl = Jurisprudence.Jurisprudence()
subdomain_ctrl = Subdomain.Subdomains()
facebook_ctrl = Facebook.Facebook()
shodan_ctrl = Shodan.Shodan()
vt_ctrl = VirusTotal.VirusTotal()


def login_required(view_func):
    """Ensure the operator is authenticated before accessing protected routes."""
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("isAuthenticated"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped


@spo.before_request
def make_session_permanent():
    session.permanent = True


@spo.after_request
def apply_security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@spo.context_processor
def inject_globals():
    uid = session.get("id")
    projects = []
    if session.get("isAuthenticated") and uid:
        try:
            projects = dao.listProjects(uid)
        except Exception:
            projects = []
    return {
        "current_user": session.get("user"),
        "user_projects": projects,
        "app_version": "2.0.0",
    }


@spo.route("/health")
def health():
    return jsonify({"status": "ok", "service": "SPO-Sneak-Peek-OSINT", "version": "2.0.0"}), 200


@spo.route("/exit")
def exit():
    session.clear()
    return redirect(url_for("login"))


@spo.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@spo.errorhandler(403)
def page_forbidden(e):
    return render_template("403.html"), 403


@spo.errorhandler(500)
def internal_error(e):
    return render_template("500.html"), 500


@spo.route("/", methods=["GET", "POST"])
def login():
    if dao.testFirstAccess():
        return redirect(url_for("wellcome"))

    if request.method == "POST":
        get_user = (request.form.get("user") or "").strip()
        get_passwd = request.form.get("password") or ""

        if dao.testLogin(get_user, get_passwd):
            session["user"] = get_user
            session["isAuthenticated"] = True
            session["id"] = dao.getIDUser(get_user)
            return redirect(url_for("dashboard"))
        return render_template("passwordFail.html"), 401

    if session.get("isAuthenticated"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@spo.route("/wellcome")
def wellcome():
    return render_template("wellcome.html")


@spo.route("/firstLogin", methods=["GET", "POST"])
def firstLogin():
    # Allow registration on first access OR when an authenticated admin registers an operator
    if not dao.testFirstAccess() and not session.get("isAuthenticated"):
        return redirect(url_for("login"))

    if request.method == "POST":
        get_user = (request.form.get("user") or "").strip()
        get_passwd = request.form.get("password") or ""
        if not get_user or not get_passwd:
            flash("Username and password are required.", "error")
            return render_template("firstLogin.html"), 400
        created_id = dao.insertUser(get_user, get_passwd)
        if created_id is None:
            flash("Invalid username characters detected.", "error")
            return render_template("firstLogin.html"), 400
        return render_template("ok_registration.html")
    return render_template("firstLogin.html")


@spo.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    uid = session.get("id")
    stats = dao.getDashboardStats(uid)
    recent_scans = dao.getRecentScans(uid, limit=10)
    projects = dao.listProjects(uid)
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent_scans,
        projects=projects,
    )


@spo.route("/companyInvestigation", methods=["GET", "POST"])
@login_required
def companyInvestigation():
    uid = session.get("id")
    subdomains = []
    subdomains_detailed = []
    domain_name = ""
    owner_domain_info = {}
    domain_info = {}
    process = {}
    treat_cnpj = ""
    selected_project_id = None

    if request.method == "POST":
        name_of_project = (request.form.get("nameOfProject") or "").strip()
        scope_of_project = (request.form.get("scopeOfProject") or "Company & Domain OSINT").strip()
        if name_of_project:
            new_pid = dao.createProject(uid, name_of_project, scope_of_project)
            if new_pid:
                selected_project_id = new_pid
                flash(f"Project '{name_of_project}' created successfully.", "success")

        raw_project_id = request.form.get("project_id")
        if raw_project_id and str(raw_project_id).isdigit():
            selected_project_id = int(raw_project_id)

        raw_domain = (request.form.get("domain") or "").strip()
        raw_cnpj = (request.form.get("cnpj_input") or "").strip()

        if raw_domain or raw_cnpj:
            if raw_domain:
                domain_name = whois_ctrl.normalize_domain(raw_domain)
                owner_domain_info = whois_ctrl.owner(domain_name)
                subdomains = subdomain_ctrl.getSubdomains(domain_name)
                subdomains_detailed = subdomain_ctrl.getSubdomainsDetailed(domain_name, resolve_limit=15)

            candidate_cnpj = raw_cnpj or (owner_domain_info.get("ownerid") if owner_domain_info else "") or ""
            cleaned_digits = cnpj_ctrl.treat(candidate_cnpj)

            if len(cleaned_digits) == 14:
                treat_cnpj = cleaned_digits
                domain_info = cnpj_ctrl.getCNPJ(cleaned_digits)
                legal_query = domain_info.get("social_name") or cnpj_ctrl.format_cnpj(cleaned_digits)
                process = lawyer_ctrl.jurisprudence(legal_query)
            elif domain_name:
                domain_info = cnpj_ctrl._empty_result()
                process = lawyer_ctrl.jurisprudence(owner_domain_info.get("owner") or domain_name)

            target_label = domain_name or cnpj_ctrl.format_cnpj(treat_cnpj)
            summary_parts = []
            if domain_info.get("social_name"):
                summary_parts.append(domain_info["social_name"])
            if owner_domain_info.get("owner"):
                summary_parts.append(f"Owner: {owner_domain_info['owner']}")
            summary_parts.append(f"{len(subdomains)} subdomains")
            summary = " • ".join(summary_parts)

            dao.saveScanResult(
                uid,
                scan_type="company",
                target=target_label,
                summary=summary,
                payload={
                    "domain": domain_name,
                    "cnpj": treat_cnpj,
                    "whois": owner_domain_info,
                    "company": domain_info,
                    "subdomains": subdomains,
                    "jurisprudence": process,
                },
                project_id=selected_project_id,
            )

    return render_template(
        "companyInvestigation.html",
        subdomain=subdomains,
        subdomains_detailed=subdomains_detailed,
        domain_name=domain_name,
        cnpj=treat_cnpj,
        ownerDomainInfo=owner_domain_info,
        domainInfo=domain_info,
        jurisprudence=process,
        selected_project_id=selected_project_id,
    )


@spo.route("/personalInvestigation", methods=["GET", "POST"])
@spo.route("/personalTrace", methods=["GET", "POST"])
@login_required
def personalInvestigation():
    uid = session.get("id")
    photo_perfil = ""
    likes_by_facebook = []
    location_by_facebook = {}
    recon = None
    selected_project_id = None

    if request.method == "POST":
        profile_input = (request.form.get("profile_facebook") or "").strip()
        email_input = (request.form.get("email") or "").strip()
        raw_project_id = request.form.get("project_id")
        if raw_project_id and str(raw_project_id).isdigit():
            selected_project_id = int(raw_project_id)

        if profile_input or email_input:
            recon = facebook_ctrl.investigate_person(profile_input or email_input, email=email_input)
            photo_perfil = recon.get("avatar_url") or ""
            likes_by_facebook = [
                f"{p['platform']}: {p['url']} ({p['details']})"
                for p in recon.get("platforms", [])
                if p.get("exists")
            ]
            gh = recon.get("github", {})
            if gh.get("location"):
                location_by_facebook["Location"] = gh["location"]
            if gh.get("company"):
                location_by_facebook["Company"] = gh["company"]
            if gh.get("blog"):
                location_by_facebook["Website"] = gh["blog"]

            dao.saveScanResult(
                uid,
                scan_type="personal",
                target=profile_input or email_input,
                summary=f"{recon.get('found_count', 0)} platforms matched • GitHub: {'Yes' if gh.get('found') else 'No'}",
                payload=recon,
                project_id=selected_project_id,
            )

    return render_template(
        "personalInvestigation.html",
        photo_perfil=photo_perfil,
        likes_by_facebook=likes_by_facebook,
        location_by_facebook=location_by_facebook,
        recon=recon,
        selected_project_id=selected_project_id,
    )


# Alias for url_for('personalTrace') compatibility
spo.add_url_rule("/personalTrace", endpoint="personalTrace", view_func=personalInvestigation, methods=["GET", "POST"])


@spo.route("/searchServers", methods=["GET", "POST"])
@login_required
def searchServers():
    uid = session.get("id")
    server_result = None
    vt_result = None
    target_query = ""
    selected_project_id = None

    if request.method == "POST":
        target_query = (request.form.get("target") or "").strip()
        raw_project_id = request.form.get("project_id")
        if raw_project_id and str(raw_project_id).isdigit():
            selected_project_id = int(raw_project_id)

        if target_query:
            shodan_row = dao.getApiKey(uid, "shodan")
            vt_row = dao.getApiKey(uid, "virustotal")
            shodan_key = shodan_row["key_value"] if shodan_row else os.environ.get("SHODAN_API_KEY")
            vt_key = vt_row["key_value"] if vt_row else os.environ.get("VIRUSTOTAL_API_KEY")

            server_result = shodan_ctrl.search(shodan_key, target_query)
            vt_result = vt_ctrl.analyzeTarget( server_result.get("ip") or target_query, api_key=vt_key)

            ports_cnt = len(server_result.get("ports", []))
            vulns_cnt = len(server_result.get("vulns", []))
            isp_label = server_result.get("geo", {}).get("isp") or "Unknown ISP"
            dao.saveScanResult(
                uid,
                scan_type="server",
                target=target_query,
                summary=f"IP: {server_result.get('ip') or 'N/A'} • {ports_cnt} open ports • {vulns_cnt} CVEs • {isp_label}",
                payload={"shodan": server_result, "threat_intel": vt_result},
                project_id=selected_project_id,
            )

    return render_template(
        "searchServers.html",
        target_query=target_query,
        server_result=server_result,
        vt_result=vt_result,
        selected_project_id=selected_project_id,
    )


@spo.route("/projects", methods=["GET", "POST"])
@login_required
def projects():
    uid = session.get("id")
    if request.method == "POST":
        name = (request.form.get("name_project") or "").strip()
        scope = (request.form.get("scope_project") or "").strip()
        if name:
            dao.createProject(uid, name, scope or "OSINT Investigation Case")
            flash(f"Project '{name}' created.", "success")
            return redirect(url_for("projects"))

    all_projects = dao.listProjects(uid)
    selected_id = request.args.get("id")
    active_project = None
    if selected_id and selected_id.isdigit():
        active_project = dao.getProject(uid, int(selected_id))
    elif all_projects:
        active_project = dao.getProject(uid, int(all_projects[0]["id_project"]))

    return render_template(
        "projects.html",
        projects=all_projects,
        active_project=active_project,
    )


@spo.route("/projects/<int:project_id>/export")
@login_required
def export_project(project_id: int):
    uid = session.get("id")
    proj = dao.getProject(uid, project_id)
    if not proj:
        return jsonify({"error": "Project not found"}), 404
    return jsonify(proj)


@spo.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id: int):
    uid = session.get("id")
    dao.deleteProject(uid, project_id)
    flash("Investigation project deleted.", "info")
    return redirect(url_for("projects"))


@spo.route("/insertKeys", methods=["GET", "POST"])
@login_required
def insertKeys():
    uid = session.get("id")

    if request.method == "POST":
        shodan_key = (request.form.get("shodan") or "").strip()
        vt_key = (request.form.get("virustotal") or "").strip()
        gh_key = (request.form.get("github") or "").strip()

        updated_any = False
        if shodan_key:
            if dao.upsertApiKey(uid, "shodan", shodan_key):
                flash("Shodan API key saved successfully.", "success")
                updated_any = True
        if vt_key:
            if dao.upsertApiKey(uid, "virustotal", vt_key):
                flash("VirusTotal v3 API key saved successfully.", "success")
                updated_any = True
        if gh_key:
            if dao.upsertApiKey(uid, "github", gh_key):
                flash("GitHub Personal Access Token saved successfully.", "success")
                updated_any = True

        if not updated_any:
            flash("No valid API key was provided.", "warning")
        return redirect(url_for("insertKeys"))

    keys = dao.getAllApiKeys(uid)
    masked_keys = {}
    for k, v in keys.items():
        if len(v) > 8:
            masked_keys[k] = f"{v[:4]}{'*' * (len(v) - 8)}{v[-4:]}"
        else:
            masked_keys[k] = "****"

    return render_template("insertKeys.html", configured_keys=masked_keys)


@spo.route("/aboutOSINT")
@login_required
def aboutOSINT():
    return render_template("aboutOSINT.html")


@spo.route("/manual")
@login_required
def manual():
    return render_template("manual.html")


@spo.route("/about")
@login_required
def aboutUS():
    return render_template("aboutus.html")


if __name__ == "__main__":
    port = int(os.environ.get("SPO_PORT", 1337))
    host = os.environ.get("SPO_HOST", "0.0.0.0")
    debug = os.environ.get("SPO_DEBUG", "false").lower() in ("1", "true", "yes")
    spo.run(host=host, port=port, debug=debug)
