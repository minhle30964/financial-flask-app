import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Loading in data from tables into variables
    trans_info = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    # Returning rendered version of index.html with variables created above
    return render_template("index.html", transactions=trans_info, user=user_info)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User submitted the buy stock form via POST method
    if request.method == "POST":

        # Confirming that the user inputted a stock stymbol
        if not request.form.get("symbol"):
            return apology("Must Specify Stock's Symbol")

        # Confirming that the stock symbol exists
        elif lookup(request.form.get("symbol")) == None:
            return apology("Stock's Symbol Does Not Exist")

        # Confirming a positive amount of shares was inputted
        if int(request.form.get("shares")) <= 0:
            return apology("Please Input A Positive Integer Amount of Shares")

        # Creating new table for transactions
        # db.execute("CREATE TABLE transactions (id INTEGER, user_id INTEGER, type TEXT NOT NULL, stock TEXT NOT NULL, number_of_shares INTEGER, individual_share_price DOUBLE, total_share_price DOUBLE, time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id))") # time DATETIME DEFAULT ON UPDATE # time TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP

        # Getting the user's cash from table
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Getting total cost of the shares
        total_cost = int(request.form.get("shares")) * lookup(request.form.get("symbol"))["price"]

        # Confirming user can afford amount of shares inputted
        if user_cash < total_cost:
            return apology("You Can't Afford That Amount of Shares at The Current Price")

        # Inserting the transaction into table
        db.execute("INSERT INTO transactions(user_id, type, stock, number_of_shares, individual_share_price, total_share_price) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], "BUY STOCK", request.form.get("symbol"), int(request.form.get("shares")), lookup(request.form.get("symbol"))["price"], total_cost)

        # Updating user's cash
        user_cash -= total_cost
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash, session["user_id"])

        # Redirecting user to homepage
        return redirect("/")

    # User accesses buy page and form via GET method
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Loading in data from tables into variables
    trans_info = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

    # Returning rendered version of index.html with variables created above
    return render_template("history.html", transactions=trans_info, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User submitted the quote form via POST method
    if request.method == "POST":

        # Looking up the stock symbol that was inputted
        quote = lookup(request.form.get("symbol"))

        # Confirming that the stock symbol that the user inputted exists
        if quote == None:
            return apology("The Stock Symbol You Inputted Does Not Exist")

        # Returning a rendered template of quoted.html with the name, price, and symbol of the stock the user inputted
        return render_template("quoted.html", name=quote["name"], price=usd(quote["price"]), symbol=quote["symbol"])

    # User accesses quote page and form via GET method
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Clearing any previous user id
    session.clear()

    # User submitted the register form via POST method
    if request.method == "POST":

        # Confirms that the user filled out all of the fields to register
        if not (request.form.get("username") and request.form.get("password") and request.form.get("confirmation")):
            return apology("Must Fill Out All Fields")

        # Confirms that the user entered the same password twice when registering
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords Do Not Match")

        # Confirms that the username that the user inputted has not been used yet
        if len(db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))) != 0:
            return apology("Username is Already Taken")

        # Adding the user's username and hashed password to the users database
        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", request.form.get(
            "username"), generate_password_hash(request.form.get("password")))

        # Logging the user in
        session["user_id"] = db.execute("SELECT id FROM users WHERE username = ?", request.form.get("username"))[0]["id"]

        # Redirecting the user to the homepage
        return redirect("/")

    # User accesses registration page and form via GET method
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User submitted the buy stock form via POST method
    if request.method == "POST":

        # Confirming that the user inputted a stock stymbol
        if not request.form.get("symbol"):
            return apology("Must Specify Stock's Symbol")

        # Confirming that the stock symbol exists
        elif lookup(request.form.get("symbol")) == None:
            return apology("Stock's Symbol Does Not Exist")

        # Confirming a positive amount of shares was inputted
        if int(request.form.get("shares")) <= 0:
            return apology("Please Input A Positive Integer Amount of Shares")

        # Redirecting the user to the homepage
        return redirect("/")

    # User accesses sell page and form via GET method
    else:
        return render_template("sell.html")


@app.route("/add-cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """Add cash to user's account"""

    # User submitted the buy stock form via POST method
    if request.method == "POST":

        # Getting the user's cash from table
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Getting amount of cash inputted by user
        amount = float(request.form.get("cash-amount"))

        # Updating user's cash
        user_cash += amount
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash, session["user_id"])

        # Redirecting the user to the homepage
        return redirect("/")

    # User accesses sell page and form via GET method
    else:
        return render_template("cash.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
