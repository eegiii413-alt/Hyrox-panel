import hmac
import logging
import os
import secrets
from datetime import date
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar, cast

import bcrypt
import httpx
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from postgrest.exceptions import APIError
from supabase import Client, create_client

load_dotenv(Path(__file__).with_name(".env"))

supabase_url = os.getenv("SUPABASE_URL")
supabase_secret_key = os.getenv("SUPABASE_SECRET_KEY")
if not supabase_url or not supabase_secret_key:
    raise RuntimeError("SUPABASE_URL болон SUPABASE_SECRET_KEY-ийг .env файлд тохируулна уу.")

supabase: Client = create_client(supabase_url, supabase_secret_key)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower() == "true",
)

if not os.getenv("FLASK_SECRET_KEY"):
    app.logger.warning("FLASK_SECRET_KEY тохируулаагүй тул түр түлхүүр ашиглаж байна.")

logging.basicConfig(level=logging.INFO)

ViewFunction = TypeVar("ViewFunction", bound=Callable[..., Any])


def login_required(view: ViewFunction) -> ViewFunction:
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any) -> Any:
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return cast(ViewFunction, wrapped_view)


@app.context_processor
def provide_csrf_token() -> dict[str, str]:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["_csrf_token"]}


def valid_csrf_token() -> bool:
    sent_token = request.form.get("csrf_token", "")
    saved_token = session.get("_csrf_token", "")
    return bool(saved_token) and hmac.compare_digest(sent_token, saved_token)


@app.get("/")
def index() -> Any:
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Хүсэлтийг баталгаажуулж чадсангүй. Дахин оролдоно уу.", "error")
            return render_template("login.html"), 400

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("И-мэйл болон нууц үгээ оруулна уу.", "error")
            return render_template("login.html"), 400

        try:
            result = (
                supabase.table("users")
                .select("id, email, password_hash")
                .eq("email", email)
                .limit(1)
                .execute()
            )
        except (APIError, httpx.HTTPError):
            app.logger.exception("Supabase-аас хэрэглэгч хайхад алдаа гарлаа.")
            flash("Сервертэй холбогдоход алдаа гарлаа. Дараа дахин оролдоно уу.", "error")
            return render_template("login.html"), 503

        user = result.data[0] if result.data else None
        password_matches = False
        if user:
            try:
                password_matches = bcrypt.checkpw(
                    password.encode("utf-8"),
                    user["password_hash"].encode("utf-8"),
                )
            except (KeyError, TypeError, ValueError):
                app.logger.exception("Хэрэглэгчийн хадгалсан нууц үгийн хэш буруу байна.")

        if not user or not password_matches:
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.get("/dashboard")
@login_required
def dashboard() -> Any:
    try:
        result = (
            supabase.table("content_drafts")
            .select("id, title, content, status, created_at")
            .order("created_at", desc=True)
            .execute()
        )
    except (APIError, httpx.HTTPError):
        app.logger.exception("Supabase-аас ноорог пост авахад алдаа гарлаа.")
        flash("Ноорог постуудыг ачаалж чадсангүй. Дараа дахин оролдоно уу.", "error")
        return render_template("dashboard.html", drafts=[]), 503

    return render_template("dashboard.html", drafts=result.data)


DRAFT_ACTIONS = {
    "approve": ("approved", "Ноорог батлагдлаа."),
    "reject": ("rejected", "Ноорогоос татгалзлаа."),
}


@app.post("/drafts/<int:draft_id>/status")
@login_required
def change_draft_status(draft_id: int) -> Any:
    if not valid_csrf_token():
        flash("Хүсэлтийг баталгаажуулж чадсангүй. Дахин оролдоно уу.", "error")
        return redirect(url_for("dashboard"))

    action = DRAFT_ACTIONS.get(request.form.get("action", ""))
    if action is None:
        flash("Үйлдэл буруу байна.", "error")
        return redirect(url_for("dashboard"))

    new_status, success_message = action
    try:
        result = (
            supabase.table("content_drafts")
            .update({"status": new_status})
            .eq("id", draft_id)
            .eq("status", "draft")
            .execute()
        )
    except (APIError, httpx.HTTPError):
        app.logger.exception("Supabase дээр ноорогийн төлөв солиход алдаа гарлаа.")
        flash("Төлөвийг сольж чадсангүй. Дараа дахин оролдоно уу.", "error")
        return redirect(url_for("dashboard"))

    if result.data:
        flash(success_message, "success")
    else:
        flash("Энэ ноорог аль хэдийн шийдвэрлэгдсэн эсвэл олдсонгүй.", "error")
    return redirect(url_for("dashboard"))


@app.get("/bookings")
@login_required
def bookings() -> Any:
    try:
        result = (
            supabase.table("bookings")
            .select("id, customer_name, email, booking_date, session_name, status, created_at")
            .order("booking_date", desc=False)
            .execute()
        )
    except (APIError, httpx.HTTPError):
        app.logger.exception("Supabase-аас захиалга авахад алдаа гарлаа.")
        flash("Захиалгуудыг ачаалж чадсангүй. Дараа дахин оролдоно уу.", "error")
        return render_template("bookings.html", bookings=[]), 503

    return render_template("bookings.html", bookings=result.data)


# ---------- Аялал, Ажилтан: нэмэх, засах, устгах, хайх ----------

ENTITIES: dict[str, dict[str, Any]] = {
    "tours": {
        "table": "tours",
        "title": "Аялал",
        "list_heading": "Аяллын",
        "subtitle": "Аяллын жагсаалт, нэмэх, засах, устгах.",
        "add_label": "Аялал нэмэх",
        "noun": "аялал",
        "display_field": "name",
        "order": ("start_date", False),
        "fields": [
            {"name": "name", "label": "Аяллын нэр", "type": "text", "required": True},
            {"name": "destination", "label": "Очих газар", "type": "text", "required": True},
            {"name": "start_date", "label": "Эхлэх огноо", "type": "date", "required": True},
            {"name": "days", "label": "Хоног", "type": "number", "required": True, "min": 1},
            {"name": "price", "label": "Үнэ (₮)", "type": "number", "required": True, "min": 0},
            {"name": "seats", "label": "Суудал", "type": "number", "required": True, "min": 0},
        ],
    },
    "staff": {
        "table": "staff",
        "title": "Ажилтан",
        "list_heading": "Ажилчдын",
        "subtitle": "Ажилчдын жагсаалт, нэмэх, засах, устгах.",
        "add_label": "Ажилтан нэмэх",
        "noun": "ажилтан",
        "display_field": "full_name",
        "order": ("full_name", False),
        "fields": [
            {"name": "full_name", "label": "Овог нэр", "type": "text", "required": True},
            {"name": "position", "label": "Албан тушаал", "type": "text", "required": True},
            {"name": "phone", "label": "Утас", "type": "tel", "required": False},
            {"name": "email", "label": "И-мэйл", "type": "email", "required": False},
        ],
    },
}


def entity_columns(entity: dict[str, Any]) -> str:
    return ", ".join(["id"] + [field["name"] for field in entity["fields"]])


def read_entity_form(entity: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Маягтын утгыг уншиж шалгана. (Supabase-д явуулах өгөгдөл, маягтад буцааж харуулах утга, алдаанууд)"""
    data: dict[str, Any] = {}
    raw: dict[str, Any] = {}
    errors: list[str] = []
    for field in entity["fields"]:
        value = request.form.get(field["name"], "").strip()
        raw[field["name"]] = value
        if not value:
            if field["required"]:
                errors.append(f"«{field['label']}» талбарыг бөглөнө үү.")
            data[field["name"]] = None
            continue
        if field["type"] == "number":
            try:
                number = int(value)
            except ValueError:
                errors.append(f"«{field['label']}» талбарт бүхэл тоо оруулна уу.")
                continue
            if number < field.get("min", 0):
                errors.append(f"«{field['label']}» {field.get('min', 0)}-ээс бага байж болохгүй.")
                continue
            data[field["name"]] = number
        elif field["type"] == "date":
            try:
                date.fromisoformat(value)
            except ValueError:
                errors.append(f"«{field['label']}» огноо буруу байна.")
                continue
            data[field["name"]] = value
        else:
            data[field["name"]] = value
    return data, raw, errors


def get_entity_row(entity: dict[str, Any], row_id: int) -> dict[str, Any] | None:
    result = (
        supabase.table(entity["table"])
        .select(entity_columns(entity))
        .eq("id", row_id)
        .limit(1)
        .execute()
    )
    return result.data[0] if result.data else None


def entity_list(key: str) -> Any:
    entity = ENTITIES[key]
    query = request.args.get("q", "").strip()
    order_column, order_desc = entity["order"]
    try:
        result = (
            supabase.table(entity["table"])
            .select(entity_columns(entity))
            .order(order_column, desc=order_desc)
            .execute()
        )
    except (APIError, httpx.HTTPError):
        app.logger.exception("Supabase-аас %s авахад алдаа гарлаа.", entity["table"])
        flash(
            f"Мэдээллийг ачаалж чадсангүй. Supabase дээр «{entity['table']}» хүснэгт үүссэн эсэхийг шалгана уу.",
            "error",
        )
        return render_template("entity_list.html", key=key, entity=entity, rows=[], total=0, q=query, active=key), 503

    rows = result.data
    total = len(rows)
    if query:
        needle = query.casefold()
        rows = [
            row for row in rows
            if any(needle in str(row.get(field["name"]) or "").casefold() for field in entity["fields"])
        ]
    return render_template("entity_list.html", key=key, entity=entity, rows=rows, total=total, q=query, active=key)


def entity_form(key: str, row_id: int | None = None) -> Any:
    entity = ENTITIES[key]
    list_url = url_for(f"{key}_list")

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Хүсэлтийг баталгаажуулж чадсангүй. Дахин оролдоно уу.", "error")
            return redirect(list_url)
        data, raw, errors = read_entity_form(entity)
        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("entity_form.html", key=key, entity=entity, row=raw, row_id=row_id, active=key), 400
        try:
            table = supabase.table(entity["table"])
            if row_id is None:
                table.insert(data).execute()
                flash(f"Шинэ {entity['noun']} нэмэгдлээ.", "success")
            else:
                result = table.update(data).eq("id", row_id).execute()
                if not result.data:
                    flash(f"Ийм {entity['noun']} олдсонгүй.", "error")
                    return redirect(list_url)
                flash("Өөрчлөлт хадгалагдлаа.", "success")
        except (APIError, httpx.HTTPError):
            app.logger.exception("Supabase дээр %s хадгалахад алдаа гарлаа.", entity["table"])
            flash("Хадгалж чадсангүй. Дараа дахин оролдоно уу.", "error")
            return render_template("entity_form.html", key=key, entity=entity, row=raw, row_id=row_id, active=key), 503
        return redirect(list_url)

    row: dict[str, Any] = {}
    if row_id is not None:
        try:
            found = get_entity_row(entity, row_id)
        except (APIError, httpx.HTTPError):
            app.logger.exception("Supabase-аас %s авахад алдаа гарлаа.", entity["table"])
            flash("Мэдээллийг ачаалж чадсангүй.", "error")
            return redirect(list_url)
        if found is None:
            flash(f"Ийм {entity['noun']} олдсонгүй.", "error")
            return redirect(list_url)
        row = found
    return render_template("entity_form.html", key=key, entity=entity, row=row, row_id=row_id, active=key)


def entity_delete(key: str, row_id: int) -> Any:
    entity = ENTITIES[key]
    list_url = url_for(f"{key}_list")

    if request.method == "POST":
        if not valid_csrf_token():
            flash("Хүсэлтийг баталгаажуулж чадсангүй. Дахин оролдоно уу.", "error")
            return redirect(list_url)
        try:
            result = supabase.table(entity["table"]).delete().eq("id", row_id).execute()
        except (APIError, httpx.HTTPError):
            app.logger.exception("Supabase дээр %s устгахад алдаа гарлаа.", entity["table"])
            flash("Устгаж чадсангүй. Дараа дахин оролдоно уу.", "error")
            return redirect(list_url)
        if result.data:
            flash(f"{entity['title']} устгагдлаа.", "success")
        else:
            flash(f"Ийм {entity['noun']} олдсонгүй.", "error")
        return redirect(list_url)

    try:
        row = get_entity_row(entity, row_id)
    except (APIError, httpx.HTTPError):
        app.logger.exception("Supabase-аас %s авахад алдаа гарлаа.", entity["table"])
        flash("Мэдээллийг ачаалж чадсангүй.", "error")
        return redirect(list_url)
    if row is None:
        flash(f"Ийм {entity['noun']} олдсонгүй.", "error")
        return redirect(list_url)
    return render_template("entity_delete.html", key=key, entity=entity, row=row, active=key)


def register_entity_routes(key: str) -> None:
    app.add_url_rule(f"/{key}", f"{key}_list", login_required(lambda: entity_list(key)), methods=["GET"])
    app.add_url_rule(f"/{key}/new", f"{key}_new", login_required(lambda: entity_form(key)), methods=["GET", "POST"])
    app.add_url_rule(
        f"/{key}/<int:row_id>/edit", f"{key}_edit",
        login_required(lambda row_id: entity_form(key, row_id)), methods=["GET", "POST"],
    )
    app.add_url_rule(
        f"/{key}/<int:row_id>/delete", f"{key}_delete",
        login_required(lambda row_id: entity_delete(key, row_id)), methods=["GET", "POST"],
    )


for entity_key in ENTITIES:
    register_entity_routes(entity_key)


@app.get("/facebook")
@login_required
def facebook() -> Any:
    return render_template("coming_soon.html", page_title="Facebook", active="facebook")


@app.get("/chat")
@login_required
def chat() -> Any:
    return render_template("coming_soon.html", page_title="Чат", active="chat")


@app.post("/logout")
@login_required
def logout() -> Any:
    if not valid_csrf_token():
        flash("Хүсэлтийг баталгаажуулж чадсангүй. Дахин оролдоно уу.", "error")
        return redirect(url_for("dashboard")), 400

    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
