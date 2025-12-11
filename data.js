const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

const seedDatabase = async (pool) => {
  try {
    console.log('--- [DATA.JS] НАЧИНАЮ ЗАПОЛНЕНИЕ БАЗЫ (ПО 100 ЗАПИСЕЙ) ---');

    // ==========================================
    // 1. ПОЛЬЗОВАТЕЛИ (1 Admin + 100 Users)
    // ==========================================
    const u = await pool.query('SELECT count(*) FROM users');
    let userIds = []; // Сюда сохраним ID созданных юзеров для использования в заказах и чатах

    if (parseInt(u.rows[0].count) === 0) {
      console.log('> Создаю пользователей (100 шт)...');
      
      // Создаем Админа
      const hashAdmin = await bcrypt.hash('Q1qqqqqq', 10);
      await pool.query(
        `INSERT INTO users (email, password, name, role, phone, status, last_login, ip, referral_code, created_at) 
         VALUES ($1, $2, 'SuperAdmin', 'admin', '+79990000000', 'active', NOW(), '127.0.0.1', $3, NOW())`,
        ['admin@mail.ru', hashAdmin, uuidv4()]
      );

      // Массив имен для рандомизации
      const firstNames = ['Алексей', 'Мария', 'Дмитрий', 'Елена', 'Иван', 'Светлана', 'Максим', 'Ольга', 'Кирилл', 'Анна'];
      const lastNames = ['Иванов(а)', 'Петров(а)', 'Сидоров(а)', 'Смирнов(а)', 'Кузнецов(а)', 'Попов(а)', 'Васильев(а)'];
      
      const hashUser = await bcrypt.hash('123456', 10);
      
      for (let i = 0; i < 100; i++) {
        const fName = firstNames[i % firstNames.length];
        const lName = lastNames[i % lastNames.length];
        const fullName = `${fName} ${lName}`;
        const email = `user${i+1}@test.com`;

        const res = await pool.query(
          `INSERT INTO users (email, password, name, role, phone, status, last_login, ip, referral_code, created_at) 
           VALUES ($1, $2, $3, 'user', $4, 'active', NOW(), '192.168.1.1', $5, NOW()) RETURNING id`,
          [email, hashUser, fullName, `+7900${1000000+i}`, uuidv4()]
        );
        userIds.push(res.rows[0].id);
      }
    } else {
      // Если пользователи уже есть, получаем их ID для связей
      const usersRes = await pool.query("SELECT id FROM users WHERE role = 'user' LIMIT 100");
      userIds = usersRes.rows.map(row => row.id);
    }

    // ==========================================
    // 2. ТОВАРЫ (100 шт) - ОБНОВЛЕННЫЕ КАРТИНКИ
    // ==========================================
    const p = await pool.query('SELECT count(*) FROM products');
    if (parseInt(p.rows[0].count) === 0) {
      console.log('> Создаю товары (100 шт)...');
      
      // Используем picsum.photos/seed/... для гарантированной работы картинок
      const baseProducts = [
        { name: 'Умная колонка Nexus Hub', category: 'Хабы', price: 8990, image: 'https://avatars.mds.yandex.net/get-mpic/5418200/2a000001919ec2eb22f7b7123b370fab2219/orig' },
        { name: 'IP Камера 360°', category: 'Камеры', price: 4500, image: 'https://avatars.mds.yandex.net/i?id=0bde5e434bf13afe06ef2ae3a64fb5594a1efa65-5220428-images-thumbs&n=13' },
        { name: 'Умная лампа RGB', category: 'Освещение', price: 1200, image: 'https://cdn1.ozone.ru/s3/multimedia-5/6071763269.jpg' },
        { name: 'Датчик движения Pro', category: 'Датчики', price: 1990, image: 'https://rs-catalog.ru/images/detailed/574/7918260.jpg' },
        { name: 'Термостат Climate Z', category: 'Климат', price: 5600, image: 'https://avatars.mds.yandex.net/get-mpic/11740777/2a0000018b3aff8d4a325275f8a2a191589e/orig' },
        { name: 'Умный замок Lock X', category: 'Безопасность', price: 12500, image: 'https://avatars.mds.yandex.net/get-mpic/5236803/img_id4232091977614223726.jpeg/orig' },
        { name: 'Розетка Wi-Fi', category: 'Питание', price: 990, image: 'https://avatars.mds.yandex.net/get-mpic/4466970/2a00000194e07c40c03940281f1349cea3ff/orig' },
        { name: 'LED Лента (5м)', category: 'Освещение', price: 2300, image: 'https://www.svetodom.ru/published/publicdata/SVETODOMRU/attachments/SC/products_pictures/buffer/a027838_9721.jpg' },
        { name: 'Датчик протечки воды', category: 'Датчики', price: 1500, image: 'https://avatars.mds.yandex.net/get-mpic/5346941/img_id8899075375583945804.jpeg/orig' },
        { name: 'Робот-пылесос CleanBot', category: 'Бытовая техника', price: 24990, image: 'https://avatars.mds.yandex.net/get-mpic/5068955/img_id7933939364246631035.jpeg/orig' }
      ];

      for (let i = 0; i < 100; i++) {
        // Используем оператор остатка %, чтобы циклично брать товары из массива
        const item = baseProducts[i % baseProducts.length];
        // Немного меняем цену и имя, чтобы товары отличались
        const finalPrice = item.price + (i * 10); 
        const finalName = `${item.name} v.${i+1}`;
        
        // Добавляем индекс к сиду картинки, чтобы у КАЖДОГО из 100 товаров была своя уникальная картинка (опционально)
        // Если хотите, чтобы у всех товаров одной категории картинка была одинаковой, уберите "-${i}" из URL ниже.
        const uniqueImage = item.image; // Или: item.image.replace('/500/500', `-${i}/500/500`);

        await pool.query(
          `INSERT INTO products (name, description, price, image, category, stock, rating, sku, created_at) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
          [finalName, `Описание товара ${item.name}. Отличный выбор для умного дома.`, finalPrice, uniqueImage, item.category, 50+i, (4 + Math.random()).toFixed(1), `SKU-${1000+i}`]
        );
      }
    }

    // ==========================================
    // 3. ЗАКАЗЫ (100 шт)
    // ==========================================
    const o = await pool.query('SELECT count(*) FROM orders');
    if (parseInt(o.rows[0].count) === 0 && userIds.length > 0) {
      console.log('> Создаю заказы (100 шт)...');
      
      const statuses = ['placed', 'processing', 'shipped', 'completed', 'cancelled'];
      
      for (let i = 1; i <= 100; i++) {
        // Выбираем случайного пользователя из созданных
        const randUid = userIds[Math.floor(Math.random() * userIds.length)];
        
        const status = statuses[i % 5];
        const payStatus = status === 'placed' ? 'pending' : 'paid';
        const total = (Math.random() * 10000 + 1000).toFixed(2);
        const orderNum = 200000 + i;
        
        await pool.query(
          `INSERT INTO orders (user_id, order_number, total, content, status, delivery_address, payment_status, payment_method, created_at) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, 'Card', NOW() - interval '${i * 3} hour')`,
          [
            randUid, 
            orderNum, 
            total, 
            `Товар Random #${i} (x${Math.ceil(Math.random()*3)})`, 
            status, 
            `Улица Пушкина, Дом ${i}`, 
            payStatus
          ]
        );
      }
    }

    // ==========================================
    // 4. СООБЩЕНИЯ (100 шт)
    // ==========================================
    const m = await pool.query('SELECT count(*) FROM messages');
    if (parseInt(m.rows[0].count) === 0) {
      console.log('> Создаю сообщения (100 шт)...');
      
      // Получаем email и имена юзеров для правдоподобности
      const usersInfo = await pool.query("SELECT email, name FROM users WHERE role = 'user' LIMIT 50");
      const uData = usersInfo.rows;

      if (uData.length > 0) {
        for (let i = 0; i < 100; i++) {
            const user = uData[i % uData.length]; // Циклично берем юзеров
            const isEven = i % 2 === 0;
            
            if (isEven) {
                // Вопрос от пользователя
                await pool.query(
                    `INSERT INTO messages (user_name, email, text, subject, is_admin, is_read, ip, created_at) 
                    VALUES ($1, $2, $3, 'Chat', FALSE, $4, '127.0.0.1', NOW() - interval '${100 - i} hour')`,
                    [user.name, user.email, `Сообщение #${i}: Помогите с настройкой устройства.`, (i % 3 === 0)] // Иногда прочитано
                );
            } else {
                // Ответ от поддержки
                await pool.query(
                    `INSERT INTO messages (user_name, email, text, subject, is_admin, is_read, created_at) 
                    VALUES ($1, $2, $3, 'Reply', TRUE, FALSE, NOW() - interval '${100 - i} hour')`,
                    ['Поддержка', user.email, `Ответ #${i}: Здравствуйте, ${user.name}! Уже разбираемся.`]
                );
            }
        }
      }
    }

    // ==========================================
    // 5. ЛОГИ (100 шт)
    // ==========================================
    const l = await pool.query('SELECT count(*) FROM logs');
    if (parseInt(l.rows[0].count) === 0) {
        console.log('> Записываю логи (100 шт)...');
        const methods = ['GET', 'POST', 'PUT', 'DELETE'];
        const urls = ['/api/products', '/api/auth/login', '/api/orders', '/api/profile'];
        
        for (let i = 1; i <= 100; i++) {
            const method = methods[i % 4];
            const url = urls[i % 4];
            const code = (i % 10 === 0) ? 400 : 200; // Каждый 10-й лог - ошибка

            await pool.query(
            `INSERT INTO logs (user_id, username, method, url, action, details, ip, status_code, timestamp) 
             VALUES (1, 'SystemBot', $1, $2, 'AUTO_TEST', $3, '127.0.0.1', $4, NOW() - interval '${i} minute')`,
             [method, url, `Generated Log Entry #${i}`, code]
            );
        }
    }

    console.log('--- [DATA.JS] ВСЕ ТАБЛИЦЫ ЗАПОЛНЕНЫ (100 ЗАПИСЕЙ) ---');
  } catch (e) {
    console.error('SEED ERROR:', e);
  }
};

module.exports = { seedDatabase };