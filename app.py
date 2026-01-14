from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this in production
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_db():
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Tickets table
    c.execute('''CREATE TABLE IF NOT EXISTS tickets
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  status TEXT DEFAULT 'Active',
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id))''')
    
    # Ticket attachments table
    c.execute('''CREATE TABLE IF NOT EXISTS ticket_attachments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  ticket_id INTEGER,
                  filename TEXT NOT NULL,
                  filepath TEXT NOT NULL,
                  uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (ticket_id) REFERENCES tickets(id))''')
    
    # Inventory table
    c.execute('''CREATE TABLE IF NOT EXISTS inventory
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  item_name TEXT NOT NULL,
                  description TEXT,
                  custodian TEXT,
                  serial_number TEXT,
                  date_of_purchase DATE,
                  warranty_date DATE,
                  status TEXT DEFAULT 'active',
                  category TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Tasks table (Trello-style)
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  column_name TEXT DEFAULT 'To Do',
                  position INTEGER DEFAULT 0,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (created_by) REFERENCES users(id))''')
    
    # Create default admin user if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        hashed_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                  ('admin', hashed_password, 'admin@example.com'))
    
    conn.commit()
    conn.close()

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('business_system.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    
    # Get statistics
    c.execute("SELECT COUNT(*) FROM tickets WHERE status != 'Done'")
    active_tickets = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM inventory WHERE status = 'active'")
    active_items = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM tasks WHERE column_name != 'Done'")
    pending_tasks = c.fetchone()[0]
    
    conn.close()
    
    return render_template('dashboard.html', 
                         active_tickets=active_tickets,
                         active_items=active_items,
                         pending_tasks=pending_tasks)

# TICKETING SYSTEM ROUTES
@app.route('/tickets')
@login_required
def tickets():
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    c.execute('''SELECT t.*, u.username 
                 FROM tickets t 
                 LEFT JOIN users u ON t.created_by = u.id 
                 ORDER BY t.created_at DESC''')
    tickets = c.fetchall()
    conn.close()
    return render_template('tickets.html', tickets=tickets)

@app.route('/tickets/add', methods=['GET', 'POST'])
@login_required
def add_ticket():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']
        
        conn = sqlite3.connect('business_system.db')
        c = conn.cursor()
        c.execute("INSERT INTO tickets (title, description, status, created_by) VALUES (?, ?, ?, ?)",
                  (title, description, status, session['user_id']))
        ticket_id = c.lastrowid
       
        # Handle file uploads
        if 'files' in request.files:
            files = request.files.getlist('files')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"{timestamp}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(filepath)
                    c.execute("INSERT INTO ticket_attachments (ticket_id, filename, filepath) VALUES (?, ?, ?)",
                             (ticket_id, filename, filepath))
        
        conn.commit()
        conn.close()
        flash('Ticket created successfully!', 'success')
        return redirect(url_for('tickets'))
    
    return render_template('add_ticket.html')

@app.route('/tickets/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_ticket(id):
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']
        
        c.execute("UPDATE tickets SET title = ?, description = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                  (title, description, status, id))
        conn.commit()
        conn.close()
        flash('Ticket updated successfully!', 'success')
        return redirect(url_for('tickets'))
    
    c.execute("SELECT * FROM tickets WHERE id = ?", (id,))
    ticket = c.fetchone()
    c.execute("SELECT * FROM ticket_attachments WHERE ticket_id = ?", (id,))
    attachments = c.fetchall()
    conn.close()
    
    return render_template('edit_ticket.html', ticket=ticket, attachments=attachments)

@app.route('/tickets/delete/<int:id>')
@login_required
def delete_ticket(id):
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    
    # Delete attachments first
    c.execute("SELECT filepath FROM ticket_attachments WHERE ticket_id = ?", (id,))
    attachments = c.fetchall()
    for att in attachments:
        if os.path.exists(att[0]):
            os.remove(att[0])
    
    c.execute("DELETE FROM ticket_attachments WHERE ticket_id = ?", (id,))
    c.execute("DELETE FROM tickets WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash('Ticket deleted successfully!', 'success')
    return redirect(url_for('tickets'))

# INVENTORY ROUTES
@app.route('/inventory')
@login_required
def inventory():
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    c.execute("SELECT * FROM inventory ORDER BY created_at DESC")
    items = c.fetchall()
    conn.close()
    return render_template('inventory.html', items=items)

@app.route('/inventory/add', methods=['GET', 'POST'])
@login_required
def add_inventory():
    if request.method == 'POST':
        item_name = request.form['item_name']
        description = request.form['description']
        custodian = request.form['custodian']
        serial_number = request.form['serial_number']
        date_of_purchase = request.form['date_of_purchase']
        warranty_date = request.form['warranty_date']
        status = request.form['status']
        category = request.form['category']
        
        conn = sqlite3.connect('business_system.db')
        c = conn.cursor()
        c.execute('''INSERT INTO inventory 
                     (item_name, description, custodian, serial_number, date_of_purchase, warranty_date, status, category)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                  (item_name, description, custodian, serial_number, date_of_purchase, warranty_date, status, category))
        conn.commit()
        conn.close()
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('inventory'))
    
    return render_template('add_inventory.html')

@app.route('/inventory/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_inventory(id):
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    
    if request.method == 'POST':
        item_name = request.form['item_name']
        description = request.form['description']
        custodian = request.form['custodian']
        serial_number = request.form['serial_number']
        date_of_purchase = request.form['date_of_purchase']
        warranty_date = request.form['warranty_date']
        status = request.form['status']
        category = request.form['category']
        
        c.execute('''UPDATE inventory SET 
                     item_name = ?, description = ?, custodian = ?, serial_number = ?, 
                     date_of_purchase = ?, warranty_date = ?, status = ?, category = ?,
                     updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?''',
                  (item_name, description, custodian, serial_number, date_of_purchase, 
                   warranty_date, status, category, id))
        conn.commit()
        conn.close()
        flash('Inventory item updated successfully!', 'success')
        return redirect(url_for('inventory'))
    
    c.execute("SELECT * FROM inventory WHERE id = ?", (id,))
    item = c.fetchone()
    conn.close()
   
    return render_template('edit_inventory.html', item=item)

@app.route('/inventory/delete/<int:id>')
@login_required
def delete_inventory(id):
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    c.execute("DELETE FROM inventory WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash('Inventory item deleted successfully!', 'success')
    return redirect(url_for('inventory'))

# TASKS ROUTES (Trello-style)
@app.route('/tasks')
@login_required
def tasks():
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    
    columns = ['To Do', 'In Progress', 'Review', 'Done']
    tasks_by_column = {}
    
    for column in columns:
        c.execute('''SELECT t.*, u.username 
                     FROM tasks t 
                     LEFT JOIN users u ON t.created_by = u.id 
                     WHERE t.column_name = ? 
                     ORDER BY t.position''', (column,))
        tasks_by_column[column] = c.fetchall()
    
    conn.close()
    return render_template('tasks.html', tasks_by_column=tasks_by_column, columns=columns)

@app.route('/tasks/add', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form.get('description', '')
    column_name = request.form.get('column_name', 'To Do')
    
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    c.execute("INSERT INTO tasks (title, description, column_name, created_by) VALUES (?, ?, ?, ?)",
              (title, description, column_name, session['user_id']))
    conn.commit()
    conn.close()
    flash('Task added successfully!', 'success')
    return redirect(url_for('tasks'))

@app.route('/tasks/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_task(id):
    if request.method == 'GET':
        conn = sqlite3.connect('business_system.db')
        c = conn.cursor()
        c.execute('''SELECT * FROM tasks WHERE id = ?''', (id,))
        task = c.fetchone()
        conn.close()
        
        if not task:
            flash('Task not found.', 'danger')
            return redirect(url_for('tasks'))
        
        columns = ['To Do', 'In Progress', 'Review', 'Done']
        return render_template('edit_task.html', task=task, columns=columns)
    
    elif request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        column_name = request.form.get('column_name')
        
        conn = sqlite3.connect('business_system.db')
        c = conn.cursor()
        c.execute("UPDATE tasks SET title = ?, description = ?, column_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                  (title, description, column_name, id))
        conn.commit()
        conn.close()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('tasks'))

@app.route('/tasks/delete/<int:id>')
@login_required
def delete_task(id):
    conn = sqlite3.connect('business_system.db')
    c = conn.cursor()
    c.execute("DELETE FROM tasks WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('tasks'))

# task routing for moving tasks between columns
@app.route('/tasks/move/<int:id>', methods=['POST'])
@login_required
def move_task(id):
    try:
        data = request.get_json()
        column_name = data.get('column_name')
        
        conn = sqlite3.connect('business_system.db')
        c = conn.cursor()
        c.execute("UPDATE tasks SET column_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                  (column_name, id))
        conn.commit()
        conn.close()
        
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}, 400

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)