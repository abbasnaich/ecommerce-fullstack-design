# center.py
import os
import psycopg2
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from psycopg2.extras import RealDictCursor
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = 'ecom123'

# Database configuration
def get_db_connection():
    return psycopg2.connect(
        host="localhost",
        database="ecommerce_db",
        user="ecommerce_user",
        password="ecom@123"
    )

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            user_type VARCHAR(20) DEFAULT 'customer' CHECK (user_type IN ('customer', 'admin')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        )
    ''')
    
    # Create products table (if not exists)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(200) NOT NULL,
            price DECIMAL(10,2) NOT NULL,
            image VARCHAR(300),
            description TEXT,
            category VARCHAR(100) NOT NULL,
            stock INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create cart_items table for persistent cart storage
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cart_items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
            quantity INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id)
        )
    ''')
    
    # Insert sample admin user with properly hashed password
    cursor.execute("SELECT COUNT(*) FROM users WHERE email = 'admin@estore.com'")
    if cursor.fetchone()[0] == 0:
        # Generate proper password hash for 'admin123'
        admin_password_hash = generate_password_hash('admin123')
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, password_hash, user_type)
            VALUES (%s, %s, %s, %s, %s)
        ''', ('Admin', 'User', 'admin@estore.com', admin_password_hash, 'admin'))
    
    # Insert sample products (if not exists)
    sample_products = [
        ('iPhone 14 Pro', 999.99, '/static/images/iphone14.jpg', 'Latest iPhone with advanced camera system', 'Electronics', 50),
        ('Samsung Galaxy S23', 849.99, '/static/images/galaxy.png', 'Powerful Android smartphone', 'Electronics', 30),
        ('Nike Air Max', 129.99, '/static/images/nike.jpeg', 'Comfortable running shoes', 'Fashion', 100),
        ('MacBook Pro', 1999.99, '/static/images/macbook.jpeg', 'Professional laptop for creators', 'Electronics', 20),
        ('Coffee Maker', 79.99, '/static/images/coffee.webp', 'Automatic drip coffee maker', 'Home', 25),
        ('Wireless Headphones', 199.99, '/static/images/headphones.jpeg', 'Noise cancelling wireless headphones', 'Electronics', 40),
        ('Yoga Mat', 29.99, '/static/images/yogamat.jpg', 'Non-slip exercise mat', 'Sports', 75),
        ('Desk Lamp', 49.99, '/static/images/lamp.png', 'LED adjustable desk lamp', 'Home', 60)
    ]
    
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        cursor.executemany('''
            INSERT INTO products (name, price, image, description, category, stock)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', sample_products)
    
    conn.commit()
    conn.close()

# Initialize database on startup
@app.before_request
def initialize():
    init_db()

# Add JWT configuration
JWT_SECRET = 'your-secret-key-change-in-production'
JWT_ALGORITHM = 'HS256'

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user = get_user_by_id(data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'Invalid token'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/products')
def admin_products():
    return render_template('admin_products.html')

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            current_user = get_user_by_id(data['user_id'])
            
            if not current_user or current_user['user_type'] != 'admin':
                return jsonify({'error': 'Admin access required'}), 403
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Helper function to get user by ID
def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT id, first_name, last_name, email, user_type FROM users WHERE id = %s AND is_active = TRUE', (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

# Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validation
        if not data.get('first_name') or not data.get('last_name') or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(data['password']) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if email already exists
        cursor.execute('SELECT id FROM users WHERE email = %s', (data['email'],))
        if cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 400
        
        # Hash password and create user
        password_hash = generate_password_hash(data['password'])
        cursor.execute('''
            INSERT INTO users (first_name, last_name, email, password_hash)
            VALUES (%s, %s, %s, %s) RETURNING id, first_name, last_name, email, user_type
        ''', (data['first_name'], data['last_name'], data['email'], password_hash))
        
        new_user = cursor.fetchone()
        conn.commit()
        conn.close()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': new_user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        return jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': new_user
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Find user by email
        cursor.execute('SELECT * FROM users WHERE email = %s AND is_active = TRUE', (data['email'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not check_password_hash(user['password_hash'], data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET, algorithm=JWT_ALGORITHM)
        
        user_data = {
            'id': user['id'],
            'first_name': user['first_name'],
            'last_name': user['last_name'],
            'email': user['email'],
            'user_type': user['user_type']
        }
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': user_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
@token_required
def logout(current_user):
    # Since we're using JWT, logout is handled client-side by removing the token
    return jsonify({'message': 'Logout successful'})

# CREATE - Add new product
@app.route('/api/products', methods=['POST'])
def create_product():
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('''
            INSERT INTO products (name, price, image, description, category, stock)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING *
        ''', (data['name'], data['price'], data['image'], data['description'], data['category'], data['stock']))
        
        new_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        return jsonify(new_product), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Get all products
@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        search = request.args.get('search', '')
        category = request.args.get('category', '')
        
        query = "SELECT * FROM products WHERE 1=1"
        params = []
        
        if search:
            query += " AND (name ILIKE %s OR description ILIKE %s)"
            params.extend([f'%{search}%', f'%{search}%'])
        
        if category:
            query += " AND category = %s"
            params.append(category)
        
        query += " ORDER BY created_at DESC"
        
        cursor.execute(query, params)
        products = cursor.fetchall()
        conn.close()
        
        return jsonify(products)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#Get single product
@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
        product = cursor.fetchone()
        conn.close()
        
        if product:
            return jsonify(product)
        else:
            return jsonify({'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Update product
@app.route('/api/products/<int:product_id>', methods=['PUT'])
def update_product(product_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('''
            UPDATE products 
            SET name = %s, price = %s, image = %s, description = %s, category = %s, stock = %s
            WHERE id = %s RETURNING *
        ''', (data['name'], data['price'], data['image'], data['description'], data['category'], data['stock'], product_id))
        
        updated_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        if updated_product:
            return jsonify(updated_product)
        else:
            return jsonify({'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

#Delete product
@app.route('/api/products/<int:product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('DELETE FROM products WHERE id = %s RETURNING *', (product_id,))
        deleted_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        if deleted_product:
            return jsonify({'message': 'Product deleted successfully'})
        else:
            return jsonify({'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# Admin Product Management Routes
@app.route('/api/admin/products', methods=['POST'])
@admin_required
def admin_create_product(current_user):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('''
            INSERT INTO products (name, price, image, description, category, stock)
            VALUES (%s, %s, %s, %s, %s, %s) RETURNING *
        ''', (data['name'], data['price'], data['image'], data['description'], data['category'], data['stock']))
        
        new_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        return jsonify(new_product), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin/products/<int:product_id>', methods=['PUT'])
@admin_required
def admin_update_product(current_user, product_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('''
            UPDATE products 
            SET name = %s, price = %s, image = %s, description = %s, category = %s, stock = %s
            WHERE id = %s RETURNING *
        ''', (data['name'], data['price'], data['image'], data['description'], data['category'], data['stock'], product_id))
        
        updated_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        if updated_product:
            return jsonify(updated_product)
        else:
            return jsonify({'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin/products/<int:product_id>', methods=['DELETE'])
@admin_required
def admin_delete_product(current_user, product_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('DELETE FROM products WHERE id = %s RETURNING *', (product_id,))
        deleted_product = cursor.fetchone()
        conn.commit()
        conn.close()
        
        if deleted_product:
            return jsonify({'message': 'Product deleted successfully'})
        else:
            return jsonify({'error': 'Product not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Frontend Routes

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if product:
        return render_template('product_detail.html', product=product)
    else:
        return "Product not found", 404

@app.route('/cart')
def cart():
    return render_template('cart.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

# Cart API endpoints with better error handling
@app.route('/api/cart/add', methods=['POST'])
@token_required
def add_to_cart(current_user):
    try:
        data = request.get_json()
        if not data or 'product_id' not in data:
            return jsonify({'error': 'Product ID is required'}), 400
            
        product_id = data['product_id']
        quantity = data.get('quantity', 1)
        
        # Validate product exists and has sufficient stock
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute('SELECT * FROM products WHERE id = %s', (product_id,))
        product = cursor.fetchone()
        
        if not product:
            conn.close()
            return jsonify({'error': 'Product not found'}), 404
            
        if product['stock'] < quantity:
            conn.close()
            return jsonify({'error': f'Only {product["stock"]} items available'}), 400
        
        # Add to cart in database
        cursor.execute('''
            INSERT INTO cart_items (user_id, product_id, quantity)
            VALUES (%s, %s, %s)
            ON CONFLICT (user_id, product_id) 
            DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity,
                         updated_at = CURRENT_TIMESTAMP
            RETURNING quantity
        ''', (current_user['id'], product_id, quantity))
        
        new_quantity = cursor.fetchone()['quantity']
        
        # Check if total quantity exceeds stock
        if new_quantity > product['stock']:
            # Adjust to max available
            cursor.execute('''
                UPDATE cart_items SET quantity = %s 
                WHERE user_id = %s AND product_id = %s
            ''', (product['stock'], current_user['id'], product_id))
            conn.commit()
            conn.close()
            return jsonify({'error': f'Maximum {product["stock"]} items available. Quantity adjusted.'}), 400
            
        conn.commit()
        
        # Get updated cart count
        cursor.execute('SELECT COUNT(*) as count FROM cart_items WHERE user_id = %s', (current_user['id'],))
        cart_count = cursor.fetchone()['count']
        
        conn.close()
        
        return jsonify({
            'success': True, 
            'cart_count': cart_count,
            'message': 'Product added to cart successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cart', methods=['GET'])
@token_required
def get_cart(current_user):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute('''
            SELECT p.*, ci.quantity, (p.price * ci.quantity) as item_total
            FROM cart_items ci
            JOIN products p ON ci.product_id = p.id
            WHERE ci.user_id = %s
        ''', (current_user['id'],))
        
        cart_items = cursor.fetchall()
        conn.close()
        
        total = sum(item['item_total'] for item in cart_items)
        
        return jsonify({
            'items': cart_items, 
            'total': round(total, 2),
            'cart_count': len(cart_items)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/cart/update', methods=['POST'])
@token_required
def update_cart(current_user):
    try:
        data = request.get_json()
        product_id = data['product_id']
        quantity = data['quantity']
        
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        if quantity <= 0:
            cursor.execute('DELETE FROM cart_items WHERE user_id = %s AND product_id = %s', 
                         (current_user['id'], product_id))
        else:
            cursor.execute('''
                UPDATE cart_items SET quantity = %s, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = %s AND product_id = %s
            ''', (quantity, current_user['id'], product_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':

    app.run(debug=True)
