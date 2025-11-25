import streamlit as st
import json
import os
import hashlib
import random
from typing import List, Dict, Any

# -------------------- CONFIG --------------------
DB_FILE = "/mnt/data/users.json"
RECHARGE_FILE = "/mnt/data/recharge_history.json"
TRANSACTION_FILE = "/mnt/data/transactions.json"

# -------------------- UTILITIES --------------------

def load_json_file(path: str) -> List[Dict[str, Any]]:
    # ensure directory exists and file created if missing
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump([], f)
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read().strip()
            if not data:
                return []
            return json.loads(data)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def save_json_file(path: str, data: Any) -> None:
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# -------------------- PASSWORD HASHING --------------------

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


# -------------------- DB HELPERS --------------------

def load_users() -> List[Dict[str, Any]]:
    return load_json_file(DB_FILE)


def save_users(users: List[Dict[str, Any]]) -> None:
    save_json_file(DB_FILE, users)


def load_recharge_history() -> List[Dict[str, Any]]:
    return load_json_file(RECHARGE_FILE)


def save_recharge_history(history: List[Dict[str, Any]]) -> None:
    save_json_file(RECHARGE_FILE, history)


def load_transactions() -> List[Dict[str, Any]]:
    return load_json_file(TRANSACTION_FILE)


def save_transactions(transactions: List[Dict[str, Any]]) -> None:
    save_json_file(TRANSACTION_FILE, transactions)


# -------------------- BUSINESS LOGIC --------------------

def generate_user_id() -> str:
    # 5 digit ID with leading zeros allowed (e.g. "00331")
    return f"{random.randint(0, 99999):05d}"


def find_user_by_username(username: str) -> Dict[str, Any]:
    users = load_users()
    for u in users:
        if u.get("username") == username:
            return u
    return None


def find_users_by_user_id(user_id: str) -> List[Dict[str, Any]]:
    if user_id is None:
        return []
    uid = str(user_id).strip()
    users = load_users()
    matched = [u for u in users if str(u.get("user_id", "")).strip() == uid and u.get("role") == "User"]
    return matched


def update_user_balance(username: str, amount: float) -> None:
    users = load_users()
    changed = False
    for u in users:
        if u.get("username") == username and u.get("role") == "User":
            u["balance"] = float(u.get("balance", 0)) + float(amount)
            changed = True
            break
    if changed:
        save_users(users)


def get_user_balance(username: str) -> float:
    u = find_user_by_username(username)
    if not u:
        return 0.0
    return float(u.get("balance", 0.0))


def get_vendor_balance(vendor_username: str) -> float:
    transactions = load_transactions()
    # vendor balance = sum of amounts where vendor == vendor_username
    return sum(float(t.get("amount", 0)) for t in transactions if t.get("vendor") == vendor_username)


# -------------------- UI HELPERS --------------------

def require_login(role: str):
    st.error(f"You must be logged in as {role} to view this page.")


# -------------------- FORMS --------------------

def register_form(role: str):
    # Only Admin can register via UI. Normal users are created by admin.
    if role != "Admin":
        st.info("Registration is only available for Admins. Please contact admin to create your account.")
        return
    st.subheader("Admin Registration")
    users = load_users()
    admin_exists = any(u.get("role") == "Admin" for u in users)
    if admin_exists or (st.session_state.get("logged_in") and st.session_state.get("role") == "Admin"):
        st.warning("An admin already exists or is currently logged in. New admin registrations are not allowed.")
        return

    username = st.text_input("Username", key="admin_reg_user")
    password = st.text_input("Password", type="password", key="admin_reg_pass")
    if st.button("Register", key="admin_reg_btn"):
        if not username or not password:
            st.error("Username and password cannot be empty.")
            return
        if any(u.get("username") == username for u in users):
            st.error("Username already exists!")
            return
        users.append({
            "username": username,
            "password": hash_password(password),
            "role": "Admin"
        })
        save_users(users)
        st.success("Registration successful! Please login.")
        st.rerun()


def login_form(role: str):
    st.subheader(f"{role} Login")
    username = st.text_input("Username", key=f"{role}_login_user")
    password = st.text_input("Password", type="password", key=f"{role}_login_pass")
    if st.button("Login", key=f"{role}_login_btn"):
        users = load_users()
        user = next((u for u in users if u.get("username") == username and u.get("role") == role), None)
        if user and verify_password(password, user.get("password", "")):
            st.session_state["logged_in"] = True
            st.session_state["role"] = role
            st.session_state["username"] = username
            st.success("Login successful!")
            st.rerun()
        else:
            st.error("Invalid credentials or role.")


# -------------------- DASHBOARDS --------------------

def admin_dashboard():
    st.header("Admin Dashboard")
    st.write(f"Welcome, {st.session_state.get('username', '')}!")

    # --- Register New Account ---
    st.subheader("Register New Account")
    account_type = st.selectbox("Select Account Type to Register", ["User", "Vendor"], key="account_type_select")

    # generate id automatically when admin clicks 'Generate ID'
    if st.button("Auto-generate ID", key="gen_id_btn"):
        st.session_state["generated_id"] = generate_user_id()
        st.rerun()

    new_id = st.text_input(f"{account_type} ID", value=st.session_state.get("generated_id", ""), key="admin_new_id")
    new_username = st.text_input(f"New {account_type} Username", key="admin_new_username")
    new_password = st.text_input(f"New {account_type} Password", type="password", key="admin_new_password")

    if st.button(f"Register {account_type}", key="admin_register_account_btn"):
        users = load_users()
        if not new_id or not new_username or not new_password:
            st.error(f"{account_type} ID, username, and password cannot be empty.")
        elif any(u.get("user_id") == new_id for u in users if u.get("user_id")):
            st.error(f"{account_type} ID already exists!")
        elif any(u.get("username") == new_username for u in users):
            st.error(f"{account_type} username already exists!")
        else:
            user_obj = {
                "user_id": new_id,
                "username": new_username,
                "password": hash_password(new_password),
                "role": account_type,
                "balance": float(0) if account_type == "User" else 0.0
            }
            users.append(user_obj)
            save_users(users)
            st.success(f"{account_type} '{new_username}' with ID '{new_id}' registered successfully!")
            st.rerun()

    # --- Delete User Account ---
    st.subheader("Delete User Account")
    delete_user_id = st.text_input("Enter User ID to Delete", key="delete_user_id")
    if st.button("Delete User", key="delete_user_btn"):
        if not delete_user_id:
            st.error("Please enter a User ID to delete.")
        else:
            users = load_users()
            # find username(s) before deleting
            users_to_delete = [u for u in users if u.get("user_id") == delete_user_id]
            if not users_to_delete:
                st.info("No user found with that User ID.")
            else:
                usernames = [u.get("username") for u in users_to_delete]
                users = [u for u in users if u.get("user_id") != delete_user_id]
                save_users(users)

                # delete related transactions and recharge history by username or user_id
                transactions = load_transactions()
                transactions = [t for t in transactions if t.get("user") not in usernames]
                save_transactions(transactions)

                recharges = load_recharge_history()
                recharges = [r for r in recharges if r.get("user_id") != delete_user_id and r.get("user") not in usernames]
                save_recharge_history(recharges)

                st.success(f"User(s) with ID '{delete_user_id}' have been deleted.")
                st.rerun()

    # --- Recharge User Balance ---
    st.subheader("Recharge User Balance")
    recharge_user_id = st.text_input("Enter User ID to Recharge", key="recharge_user_id")
    users = load_users()
    matched_users = [u for u in users if u.get("user_id") == recharge_user_id and u.get("role") == "User"]
    if recharge_user_id:
        if matched_users:
            selected_username = st.selectbox("Select Username Associated with User ID", [u.get("username") for u in matched_users], key="recharge_username_select")
            amount = st.number_input("Recharge Amount (Max ₹1800)", min_value=1.0, max_value=1800.0, step=1.0, key="recharge_amount")
            if st.button("Recharge", key="admin_recharge_btn"):
                if amount <= 0:
                    st.error("Enter a valid amount.")
                else:
                    update_user_balance(selected_username, float(amount))
                    history = load_recharge_history()
                    history.append({
                        "admin": st.session_state.get("username", ""),
                        "user": selected_username,
                        "user_id": recharge_user_id,
                        "amount": float(amount),
                        "balance": get_user_balance(selected_username)
                    })
                    save_recharge_history(history)
                    st.success(f"Recharged ₹{amount} to {selected_username} (ID: {recharge_user_id}). New balance: ₹{get_user_balance(selected_username)}")
                    st.rerun()
        else:
            st.info("No user found with this User ID.")
    else:
        st.info("Please enter a User ID to begin recharge.")

    # --- Recharge History ---
    st.subheader("Recharge History")
    history = load_recharge_history()
    if history:
        # show most recent first
        st.table(list(reversed(history)))
    else:
        st.info("No recharge history found.")

    # --- Vendor Total Balances ---
    st.subheader("Vendor Total Balances")
    vendors = [u for u in load_users() if u.get("role") == "Vendor"]
    vendor_balances = [{"Vendor": v.get("username"), "Total Balance": get_vendor_balance(v.get("username"))} for v in vendors]
    if vendor_balances:
        st.table(vendor_balances)
    else:
        st.info("No vendors found.")

    # --- All Vendor Transaction History ---
    st.subheader("All Vendor Transaction History")
    transactions = load_transactions()
    users_dict = {u.get("username"): u.get("user_id", "") for u in load_users() if u.get("role") == "User"}
    for vendor in vendors:
        vendor_name = vendor.get("username")
        st.markdown(f"**Vendor: {vendor_name}**")
        vendor_transactions = [
            {"user": t.get("user"), "user_id": users_dict.get(t.get("user"), ""), "vendor": t.get("vendor"), "amount": t.get("amount")}
            for t in transactions if t.get("vendor") == vendor_name
        ]
        if vendor_transactions:
            st.table(vendor_transactions)
        else:
            st.info("No transactions for this vendor.")

    # --- All User Transaction History (selected) ---
    user_list = [u.get("username") for u in load_users() if u.get("role") == "User"]

    st.subheader("View Selected User's Transaction History")
    if user_list:
        selected_user_for_history = st.selectbox("Select User to View Transaction History", user_list, key="history_user_select")
        selected_user_id = users_dict.get(selected_user_for_history, "")
        selected_user_transactions = [
            {"user": t.get("user"), "user_id": selected_user_id, "vendor": t.get("vendor"), "amount": t.get("amount")}
            for t in transactions if t.get("user") == selected_user_for_history
        ]
        if selected_user_transactions:
            st.table(selected_user_transactions)
        else:
            st.info("No transactions for this user.")
    else:
        st.info("No users found to view history.")

    st.subheader("All User Transaction History")
    for user in user_list:
        st.markdown(f"**User: {user}**")
        user_id = users_dict.get(user, "")
        user_transactions = [
            {"user": t.get("user"), "user_id": user_id, "vendor": t.get("vendor"), "amount": t.get("amount")}
            for t in transactions if t.get("user") == user
        ]
        if user_transactions:
            st.table(user_transactions)
        else:
            st.info("No transactions for this user.")

    # --- Tally Summary ---
    st.subheader("📊 Tally Summary")
    total_user_transactions = sum(float(t.get("amount", 0)) for t in transactions if t.get("user") in user_list)
    total_vendor_balance = sum(get_vendor_balance(v.get("username")) for v in vendors)

    col1, col2 = st.columns(2)
    col1.metric("Total Amount from All User Transactions", f"₹{total_user_transactions}")
    col2.metric("Total Vendor Balance", f"₹{total_vendor_balance}")


def vendor_dashboard():
    st.header("Vendor Dashboard")
    vendor_username = st.session_state.get('username', '')
    st.write(f"Welcome, {vendor_username}!")

    balance = get_vendor_balance(vendor_username)
    st.subheader("Wallet Balance")
    st.info(f"₹{balance}")

    st.subheader("Transaction History")
    transactions = [t for t in load_transactions() if t.get("vendor") == vendor_username]
    users_dict = {u.get("username"): u.get("user_id", "") for u in load_users() if u.get("role") == "User"}
    if transactions:
        transactions_with_id = [{"user": t.get("user"), "user_id": users_dict.get(t.get("user"), ""), "amount": t.get("amount")} for t in transactions]
        st.table(transactions_with_id)
    else:
        st.info("No transactions found.")


def user_dashboard():
    st.header("User Dashboard")
    username = st.session_state.get('username', '')
    st.write(f"Welcome, {username}!")

    users = load_users()
    user_id = next((u.get("user_id", "N/A") for u in users if u.get("username") == username and u.get("role") == "User"), "N/A")
    st.write(f"**User ID:** {user_id}")

    balance = get_user_balance(username)
    st.subheader("Wallet Balance")
    st.info(f"₹{balance}")

    st.subheader("Pay to Vendor")
    vendors = [u for u in load_users() if u.get("role") == "Vendor"]
    vendor_names = [v.get("username") for v in vendors]
    if not vendor_names:
        st.info("No vendors available to pay.")
    else:
        selected_vendor = st.selectbox("Select Vendor", vendor_names, key="user_select_vendor")
        amount = st.number_input("Amount to Pay", min_value=1.0, step=1.0, key="user_pay_amount")
        if st.button("Pay", key="user_pay_btn"):
            if amount <= 0:
                st.error("Enter a valid amount.")
            elif balance >= amount:
                update_user_balance(username, -float(amount))
                transactions = load_transactions()
                transactions.append({"user": username, "vendor": selected_vendor, "amount": float(amount)})
                save_transactions(transactions)
                st.success(f"Paid ₹{amount} to {selected_vendor}. New balance: ₹{get_user_balance(username)}")
                st.rerun()
            else:
                st.error("Insufficient balance.")

    st.subheader("Transaction History")
    transactions = [t for t in load_transactions() if t.get("user") == username]
    if transactions:
        transactions_with_id = [{"user": t.get("user"), "user_id": user_id, "vendor": t.get("vendor"), "amount": t.get("amount")} for t in transactions]
        st.table(transactions_with_id)
    else:
        st.info("No transactions found.")

    st.subheader("Change Password")
    new_password = st.text_input("New Password", type="password", key="change_pass")
    if st.button("Change Password", key="change_pass_btn"):
        if not new_password:
            st.error("Password cannot be empty.")
        else:
            users = load_users()
            for user in users:
                if user.get("username") == username and user.get("role") == "User":
                    user["password"] = hash_password(new_password)
                    save_users(users)
                    st.success("Password changed successfully!")
                    st.rerun()
                    break


# -------------------- MAIN --------------------

def main():
    st.title("Canteen Coupon System")
    st.sidebar.title("Select Role")

    role = st.sidebar.selectbox("Role", ["Admin", "Vendor", "User"])

    if "logged_in" not in st.session_state:
        st.session_state["logged_in"] = False

    if not st.session_state["logged_in"]:
        action = st.radio("Choose Action", ["Login", "Register"], key="choose_action")
        if action == "Login":
            login_form(role)
        else:
            register_form(role)
    else:
        if st.button("Logout"):
            st.session_state["logged_in"] = False
            st.session_state["username"] = ""
            st.session_state["role"] = ""
            st.rerun()

        if st.session_state.get("role") == "Admin":
            admin_dashboard()
        elif st.session_state.get("role") == "Vendor":
            vendor_dashboard()
        elif st.session_state.get("role") == "User":
            user_dashboard()


if __name__ == "__main__":
    main()








