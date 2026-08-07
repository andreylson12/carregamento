"use strict";

const crypto = require("crypto");
const path = require("path");
const express = require("express");
const { Pool } = require("pg");

const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const TOKEN_SECRET = process.env.TOKEN_SECRET;

const PRESENCE_INTERVAL_SECONDS = 60;
const PRESENCE_STALE_SECONDS = 180;
const PRESENCE_OUTSIDE_GRACE_SECONDS = 300;
const PRESENCE_MAX_ACCURACY_METERS = 100;

if (!DATABASE_URL) {
  console.error("ERRO: configure a variável DATABASE_URL.");
  process.exit(1);
}

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 6) {
  console.error("ERRO: configure ADMIN_PASSWORD com pelo menos 6 caracteres.");
  process.exit(1);
}

if (!TOKEN_SECRET || TOKEN_SECRET.length < 24) {
  console.error("ERRO: configure TOKEN_SECRET com pelo menos 24 caracteres.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

const app = express();

app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "50kb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "geolocation=(self)");
  next();
});

function createRateLimiter({ windowMs, max, message }) {
  const hits = new Map();

  return (req, res, next) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const current = hits.get(key);

    if (!current || current.resetAt <= now) {
      hits.set(key, {
        count: 1,
        resetAt: now + windowMs,
      });

      return next();
    }

    current.count += 1;

    if (current.count > max) {
      return res.status(429).json({
        error: message,
      });
    }

    next();
  };
}

const publicWriteLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 200,
  message: "Muitas tentativas neste aparelho/rede. Aguarde alguns minutos.",
});

const presenceLimiter = createRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
  message: "Muitas atualizações de localização. Aguarde alguns instantes.",
});

const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Muitas tentativas de acesso. Aguarde alguns minutos.",
});

function normalizePlate(value) {
  return String(value || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .slice(0, 7);
}

function isValidPlate(plate) {
  return /^[A-Z]{3}[0-9][A-Z0-9][0-9]{2}$/.test(plate);
}

function cleanText(value, maxLength) {
  return String(value || "")
    .replace(/[<>]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function isFiniteCoordinate(value, min, max) {
  const number = Number(value);

  return (
    Number.isFinite(number) &&
    number >= min &&
    number <= max
  );
}

function normalizeAccuracy(value) {
  const accuracy = Number(value);

  if (
    !Number.isFinite(accuracy) ||
    accuracy < 0 ||
    accuracy > 5000
  ) {
    return null;
  }

  return Math.round(accuracy);
}

function distanceMeters(lat1, lon1, lat2, lon2) {
  const earthRadius = 6_371_000;

  const toRadians = (degree) =>
    (degree * Math.PI) / 180;

  const deltaLat = toRadians(lat2 - lat1);
  const deltaLon = toRadians(lon2 - lon1);

  const a =
    Math.sin(deltaLat / 2) ** 2 +
    Math.cos(toRadians(lat1)) *
      Math.cos(toRadians(lat2)) *
      Math.sin(deltaLon / 2) ** 2;

  return (
    earthRadius *
    2 *
    Math.atan2(
      Math.sqrt(a),
      Math.sqrt(1 - a)
    )
  );
}

function safeCompare(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return (
    left.length === right.length &&
    crypto.timingSafeEqual(left, right)
  );
}

function createAdminToken() {
  const payload = JSON.stringify({
    exp:
      Date.now() +
      12 * 60 * 60 * 1000,

    nonce:
      crypto
        .randomBytes(16)
        .toString("hex"),
  });

  const encoded = Buffer.from(payload).toString(
    "base64url"
  );

  const signature = crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(encoded)
    .digest("base64url");

  return `${encoded}.${signature}`;
}

function verifyAdminToken(token) {
  try {
    const [encoded, signature] = String(
      token || ""
    ).split(".");

    if (!encoded || !signature) {
      return false;
    }

    const expected = crypto
      .createHmac("sha256", TOKEN_SECRET)
      .update(encoded)
      .digest("base64url");

    if (!safeCompare(signature, expected)) {
      return false;
    }

    const payload = JSON.parse(
      Buffer.from(
        encoded,
        "base64url"
      ).toString("utf8")
    );

    return Number(payload.exp) > Date.now();
  } catch {
    return false;
  }
}

function requireAdmin(req, res, next) {
  const header =
    req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!verifyAdminToken(token)) {
    return res.status(401).json({
      error: "Sessão inválida ou expirada.",
    });
  }

  next();
}

function elapsedSeconds(value, now = Date.now()) {
  if (!value) {
    return null;
  }

  const timestamp = new Date(value).getTime();

  if (!Number.isFinite(timestamp)) {
    return null;
  }

  return Math.max(
    0,
    Math.floor((now - timestamp) / 1000)
  );
}

function presenceSnapshot(
  row,
  radiusMeters,
  now = Date.now()
) {
  const radius = Number(radiusMeters);

  const lastDistance =
    row.last_presence_distance_m == null
      ? null
      : Number(
          row.last_presence_distance_m
        );

  const lastAccuracy =
    row.last_presence_accuracy_m == null
      ? null
      : Number(
          row.last_presence_accuracy_m
        );

  const ageSeconds = elapsedSeconds(
    row.last_presence_at,
    now
  );

  const outsideSeconds = elapsedSeconds(
    row.outside_since,
    now
  );

  const base = {
    required: Boolean(
      row.presence_required
    ),

    state: "legacy",
    label: "Cadastro anterior",
    detail: "Sem verificação periódica.",

    canCall: true,
    blockReason: null,

    lastSeenAt:
      row.last_presence_at || null,

    ageSeconds,

    outsideSince:
      row.outside_since || null,

    outsideSeconds,

    distanceMeters: lastDistance,
    accuracyMeters: lastAccuracy,
    radiusMeters: radius,

    intervalSeconds:
      PRESENCE_INTERVAL_SECONDS,

    staleSeconds:
      PRESENCE_STALE_SECONDS,

    outsideGraceSeconds:
      PRESENCE_OUTSIDE_GRACE_SECONDS,

    maxAccuracyMeters:
      PRESENCE_MAX_ACCURACY_METERS,
  };

  if (row.manual) {
    return {
      ...base,

      state: "manual",
      label: "Inclusão manual",

      detail:
        "Presença confirmada pelo responsável.",
    };
  }

  if (!row.presence_required) {
    return base;
  }

  if (
    !row.last_presence_at ||
    lastDistance == null
  ) {
    return {
      ...base,

      state: "pending",
      label: "Aguardando GPS",

      detail:
        "O motorista precisa abrir o aplicativo.",

      canCall: false,

      blockReason:
        "Ainda não há uma verificação recente da localização deste caminhão.",
    };
  }

  if (
    outsideSeconds != null &&
    outsideSeconds >=
      PRESENCE_OUTSIDE_GRACE_SECONDS
  ) {
    const minutes = Math.max(
      1,
      Math.floor(outsideSeconds / 60)
    );

    return {
      ...base,

      state: "outside",
      label: "Fora da unidade",

      detail:
        `Fora do raio há ${minutes} min.`,

      canCall: false,

      blockReason:
        `Este caminhão está fora da área permitida há aproximadamente ${minutes} minuto(s).`,
    };
  }

  /*
   * Localização antiga continua aparecendo,
   * mas não bloqueia a chamada.
   */
  if (
    ageSeconds != null &&
    ageSeconds > PRESENCE_STALE_SECONDS
  ) {
    const minutes = Math.max(
      1,
      Math.floor(ageSeconds / 60)
    );

    return {
      ...base,

      state: "stale",
      label: "Localização antiga",

      detail:
        `Sem atualização há ${minutes} min.`,

      canCall: true,
      blockReason: null,
    };
  }

  if (
    lastAccuracy != null &&
    lastAccuracy >
      PRESENCE_MAX_ACCURACY_METERS
  ) {
    return {
      ...base,

      state: "inaccurate",
      label: "GPS impreciso",

      detail:
        `Precisão aproximada: ${lastAccuracy} m.`,

      canCall: false,

      blockReason:
        `A precisão atual do GPS é de aproximadamente ${lastAccuracy} metros.`,
    };
  }

  if (lastDistance > radius) {
    const remaining = Math.max(
      0,
      PRESENCE_OUTSIDE_GRACE_SECONDS -
        (outsideSeconds || 0)
    );

    return {
      ...base,

      state: "outside_grace",
      label: "Fora do raio",

      detail:
        `Distância atual: ${lastDistance} m. Tolerância: ${Math.ceil(
          remaining / 60
        )} min.`,

      canCall: false,

      blockReason:
        `Este caminhão está fora do raio permitido. Distância aproximada: ${lastDistance} metros.`,
    };
  }

  return {
    ...base,

    state: "inside",
    label: "Dentro da unidade",

    detail:
      `Distância atual: ${lastDistance} m.`,
  };
}

async function audit(
  action,
  details = {},
  client = pool
) {
  await client.query(
    `
      INSERT INTO audit_logs (
        action,
        details
      )
      VALUES (
        $1,
        $2::jsonb
      )
    `,
    [
      action,
      JSON.stringify(details),
    ]
  );
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      id SMALLINT PRIMARY KEY CHECK (id = 1),

      unit_name VARCHAR(120) NOT NULL,

      daily_code VARCHAR(12) NOT NULL,

      latitude DOUBLE PRECISION NOT NULL,

      longitude DOUBLE PRECISION NOT NULL,

      radius_m INTEGER NOT NULL
        CHECK (
          radius_m BETWEEN 20 AND 10000
        ),

      block_device BOOLEAN
        NOT NULL
        DEFAULT TRUE,

      updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS queue_entries (
      id UUID PRIMARY KEY,

      plate VARCHAR(7) NOT NULL,

      driver_name VARCHAR(120)
        NOT NULL,

      carrier VARCHAR(160)
        NOT NULL,

      status VARCHAR(20)
        NOT NULL
        DEFAULT 'aguardando'
        CHECK (
          status IN (
            'aguardando',
            'chamado',
            'balanca',
            'finalizado'
          )
        ),

      arrival_time TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      distance_m INTEGER,

      latitude DOUBLE PRECISION,

      longitude DOUBLE PRECISION,

      device_id VARCHAR(120),

      manual BOOLEAN
        NOT NULL
        DEFAULT FALSE
    );

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      presence_required BOOLEAN
      NOT NULL
      DEFAULT FALSE;

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      last_presence_at TIMESTAMPTZ;

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      last_presence_latitude
      DOUBLE PRECISION;

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      last_presence_longitude
      DOUBLE PRECISION;

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      last_presence_distance_m
      INTEGER;

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      last_presence_accuracy_m
      INTEGER;

    ALTER TABLE queue_entries
      ADD COLUMN IF NOT EXISTS
      outside_since TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,

      action VARCHAR(80) NOT NULL,

      details JSONB
        NOT NULL
        DEFAULT '{}'::jsonb,

      created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
    );

    CREATE UNIQUE INDEX IF NOT EXISTS
      uq_queue_active_plate

      ON queue_entries (plate)

      WHERE status IN (
        'aguardando',
        'chamado',
        'balanca'
      );

    CREATE INDEX IF NOT EXISTS
      ix_queue_status_arrival

      ON queue_entries (
        status,
        arrival_time
      );

    CREATE INDEX IF NOT EXISTS
      ix_queue_device

      ON queue_entries (
        device_id,
        status
      );

    CREATE INDEX IF NOT EXISTS
      ix_queue_presence

      ON queue_entries (
        presence_required,
        last_presence_at
      )

      WHERE status = 'aguardando';
  `);

  const existing = await pool.query(
    `
      SELECT id
      FROM settings
      WHERE id = 1
    `
  );

  if (existing.rowCount === 0) {
    const initialCode =
      cleanText(
        process.env.DAILY_CODE,
        12
      ) ||
      String(
        crypto.randomInt(
          1000,
          10000
        )
      );

    const initialLat = Number(
      process.env.UNIT_LAT || 0
    );

    const initialLon = Number(
      process.env.UNIT_LON || 0
    );

    const initialRadius = Math.max(
      20,
      Number(
        process.env.RADIUS_METERS ||
          200
      )
    );

    const blockDevice =
      String(
        process.env.BLOCK_DEVICE ||
          "true"
      ).toLowerCase() !== "false";

    await pool.query(
      `
        INSERT INTO settings (
          id,
          unit_name,
          daily_code,
          latitude,
          longitude,
          radius_m,
          block_device
        )
        VALUES (
          1,
          $1,
          $2,
          $3,
          $4,
          $5,
          $6
        )
      `,
      [
        cleanText(
          process.env.UNIT_NAME,
          120
        ) ||
          "Unidade de Carregamento",

        initialCode,

        Number.isFinite(initialLat)
          ? initialLat
          : 0,

        Number.isFinite(initialLon)
          ? initialLon
          : 0,

        Number.isFinite(initialRadius)
          ? initialRadius
          : 200,

        blockDevice,
      ]
    );
  }
}

app.get(
  "/api/health",
  async (_req, res) => {
    try {
      await pool.query("SELECT 1");

      res.json({
        ok: true,
        version: "15.1.3",
      });
    } catch (error) {
      console.error(error);

      res.status(503).json({
        ok: false,
      });
    }
  }
);

app.get(
  "/api/public-config",
  async (_req, res, next) => {
    try {
      const result = await pool.query(
        `
          SELECT
            unit_name,
            radius_m
          FROM settings
          WHERE id = 1
        `
      );

      res.json({
        unitName:
          result.rows[0].unit_name,

        radiusMeters:
          result.rows[0].radius_m,

        presenceIntervalSeconds:
          PRESENCE_INTERVAL_SECONDS,

        presenceStaleSeconds:
          PRESENCE_STALE_SECONDS,

        presenceOutsideGraceSeconds:
          PRESENCE_OUTSIDE_GRACE_SECONDS,

        presenceMaxAccuracyMeters:
          PRESENCE_MAX_ACCURACY_METERS,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/queue",
  publicWriteLimiter,
  async (req, res, next) => {
    const client = await pool.connect();

    try {
      const plate = normalizePlate(
        req.body.plate
      );

      const driverName = cleanText(
        req.body.driverName,
        120
      );

      const carrier = cleanText(
        req.body.carrier,
        160
      );

      const dailyCode = cleanText(
        req.body.dailyCode,
        12
      );

      const deviceId = cleanText(
        req.body.deviceId,
        120
      );

      const latitude = Number(
        req.body.latitude
      );

      const longitude = Number(
        req.body.longitude
      );

      const accuracy = normalizeAccuracy(
        req.body.accuracy
      );

      const presenceVersion = Number(
        req.body.presenceVersion || 0
      );

      const presenceRequired =
        presenceVersion >= 15;

      if (!isValidPlate(plate)) {
        return res.status(400).json({
          error: "Placa inválida.",
        });
      }

      if (driverName.length < 3) {
        return res.status(400).json({
          error:
            "Informe o nome do motorista.",
        });
      }

      if (carrier.length < 2) {
        return res.status(400).json({
          error:
            "Informe a transportadora.",
        });
      }

      if (!deviceId) {
        return res.status(400).json({
          error:
            "Não foi possível identificar o aparelho.",
        });
      }

      if (
        !isFiniteCoordinate(
          latitude,
          -90,
          90
        ) ||
        !isFiniteCoordinate(
          longitude,
          -180,
          180
        )
      ) {
        return res.status(400).json({
          error: "Localização inválida.",
        });
      }

      await client.query("BEGIN");

      const settingsResult =
        await client.query(
          `
            SELECT *
            FROM settings
            WHERE id = 1
            FOR SHARE
          `
        );

      const settings =
        settingsResult.rows[0];

      if (
        !safeCompare(
          dailyCode,
          settings.daily_code
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(403).json({
          error:
            "Código do dia incorreto.",
        });
      }

      if (
        Number(settings.latitude) === 0 &&
        Number(settings.longitude) === 0
      ) {
        await client.query("ROLLBACK");

        return res.status(503).json({
          error:
            "A localização da unidade ainda não foi configurada pelo responsável.",
        });
      }

      const distance = Math.round(
        distanceMeters(
          latitude,
          longitude,
          Number(settings.latitude),
          Number(settings.longitude)
        )
      );

      if (
        distance >
        Number(settings.radius_m)
      ) {
        await client.query("ROLLBACK");

        return res.status(403).json({
          error:
            `Você está fora da área permitida. Distância aproximada: ${distance} m.`,
        });
      }

      if (settings.block_device) {
        const deviceCheck =
          await client.query(
            `
              SELECT id
              FROM queue_entries
              WHERE device_id = $1
                AND status IN (
                  'aguardando',
                  'chamado',
                  'balanca'
                )
              LIMIT 1
            `,
            [deviceId]
          );

        if (deviceCheck.rowCount > 0) {
          await client.query("ROLLBACK");

          return res.status(409).json({
            error:
              "Este aparelho já possui uma placa ativa na fila.",
          });
        }
      }

      const id = crypto.randomUUID();

      let inserted;

      /*
       * Cadastro V15 com presença.
       */
      if (presenceRequired) {
        inserted = await client.query(
          `
            INSERT INTO queue_entries (
              id,
              plate,
              driver_name,
              carrier,
              distance_m,
              latitude,
              longitude,
              device_id,
              presence_required,
              last_presence_at,
              last_presence_latitude,
              last_presence_longitude,
              last_presence_distance_m,
              last_presence_accuracy_m,
              outside_since
            )
            VALUES (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8,
              TRUE,
              NOW(),
              $6,
              $7,
              $5,
              $9::integer,
              NULL
            )
            RETURNING *
          `,
          [
            id,
            plate,
            driverName,
            carrier,
            distance,
            latitude,
            longitude,
            deviceId,
            accuracy,
          ]
        );
      } else {
        /*
         * Compatibilidade com versões antigas.
         */
        inserted = await client.query(
          `
            INSERT INTO queue_entries (
              id,
              plate,
              driver_name,
              carrier,
              distance_m,
              latitude,
              longitude,
              device_id,
              presence_required
            )
            VALUES (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8,
              FALSE
            )
            RETURNING *
          `,
          [
            id,
            plate,
            driverName,
            carrier,
            distance,
            latitude,
            longitude,
            deviceId,
          ]
        );
      }

      /*
       * Calcula a posição diretamente pelo ID.
       * Isso evita o erro de posição 0.
       */
      const positionResult =
        await client.query(
          `
            SELECT
              COUNT(*)::int AS position

            FROM queue_entries q

            CROSS JOIN queue_entries target

            WHERE target.id = $1

              AND q.status IN (
                'aguardando',
                'chamado',
                'balanca'
              )

              AND (
                q.arrival_time,
                q.id
              ) <= (
                target.arrival_time,
                target.id
              )
          `,
          [
            inserted.rows[0].id,
          ]
        );

      await audit(
        "PUBLIC_QUEUE_CREATED",
        {
          id,
          plate,
          distanceM: distance,

          presenceMonitoring:
            presenceRequired,

          presenceVersion,
        },
        client
      );

      await client.query("COMMIT");

      res.status(201).json({
        ...inserted.rows[0],

        position:
          positionResult.rows[0].position,

        presenceRequired,

        presence: presenceSnapshot(
          inserted.rows[0],
          settings.radius_m
        ),
      });
    } catch (error) {
      await client
        .query("ROLLBACK")
        .catch(() => {});

      if (error.code === "23505") {
        return res.status(409).json({
          error:
            "Esta placa já está ativa na fila.",
        });
      }

      next(error);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/queue/:id/presence",
  presenceLimiter,
  async (req, res, next) => {
    const client = await pool.connect();

    try {
      const deviceId = cleanText(
        req.body.deviceId,
        120
      );

      const latitude = Number(
        req.body.latitude
      );

      const longitude = Number(
        req.body.longitude
      );

      const accuracy = normalizeAccuracy(
        req.body.accuracy
      );

      if (!deviceId) {
        return res.status(400).json({
          error:
            "Não foi possível identificar o aparelho.",
        });
      }

      if (
        !isFiniteCoordinate(
          latitude,
          -90,
          90
        ) ||
        !isFiniteCoordinate(
          longitude,
          -180,
          180
        )
      ) {
        return res.status(400).json({
          error: "Localização inválida.",
        });
      }

      await client.query("BEGIN");

      const currentResult =
        await client.query(
          `
            SELECT
              q.*,

              s.latitude AS
                unit_latitude,

              s.longitude AS
                unit_longitude,

              s.radius_m

            FROM queue_entries q

            CROSS JOIN settings s

            WHERE q.id = $1
              AND s.id = 1

            FOR UPDATE OF q
          `,
          [req.params.id]
        );

      if (currentResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Registro não encontrado.",
        });
      }

      const current =
        currentResult.rows[0];

      if (
        !safeCompare(
          deviceId,
          current.device_id || ""
        )
      ) {
        await client.query("ROLLBACK");

        return res.status(403).json({
          error:
            "Este aparelho não pertence a este registro da fila.",
        });
      }

      if (
        current.status !== "aguardando"
      ) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "A verificação foi encerrada porque o caminhão não está mais aguardando.",

          active: false,

          status: current.status,
        });
      }

      if (!current.presence_required) {
        await client.query("ROLLBACK");

        return res.json({
          active: false,

          status: current.status,

          presenceRequired: false,

          presence: presenceSnapshot(
            current,
            current.radius_m
          ),
        });
      }

      const distance = Math.round(
        distanceMeters(
          latitude,
          longitude,

          Number(
            current.unit_latitude
          ),

          Number(
            current.unit_longitude
          )
        )
      );

      /*
       * V15.1.3:
       * tipos explícitos nos parâmetros.
       * Corrige PostgreSQL 42P08:
       * "inconsistent types deduced for parameter".
       */
      const updatedResult =
        await client.query(
          `
            UPDATE queue_entries

            SET
              last_presence_at = NOW(),

              last_presence_latitude =
                $1::double precision,

              last_presence_longitude =
                $2::double precision,

              last_presence_distance_m =
                $3::integer,

              last_presence_accuracy_m =
                $4::integer,

              outside_since = CASE

                WHEN
                  $4::integer IS NOT NULL
                  AND
                  $4::integer >
                  $5::integer

                THEN outside_since

                WHEN
                  $3::integer >
                  $6::integer

                THEN COALESCE(
                  outside_since,
                  NOW()
                )

                ELSE NULL

              END

            WHERE id = $7::uuid

            RETURNING *
          `,
          [
            latitude,
            longitude,
            distance,
            accuracy,

            PRESENCE_MAX_ACCURACY_METERS,

            Number(
              current.radius_m
            ),

            req.params.id,
          ]
        );

      const updated =
        updatedResult.rows[0];

      if (
        !current.outside_since &&
        updated.outside_since
      ) {
        await audit(
          "PRESENCE_OUTSIDE_STARTED",
          {
            id: updated.id,

            plate: updated.plate,

            distanceM: distance,
          },
          client
        );
      } else if (
        current.outside_since &&
        !updated.outside_since
      ) {
        await audit(
          "PRESENCE_RETURNED",
          {
            id: updated.id,

            plate: updated.plate,

            distanceM: distance,
          },
          client
        );
      }

      await client.query("COMMIT");

      res.json({
        active: true,

        status: updated.status,

        presenceRequired: true,

        presence: presenceSnapshot(
          updated,
          current.radius_m
        ),
      });
    } catch (error) {
      await client
        .query("ROLLBACK")
        .catch(() => {});

      next(error);
    } finally {
      client.release();
    }
  }
);

app.get(
  "/api/queue/:id/status",
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `
          SELECT
            q.*,
            s.radius_m

          FROM queue_entries q

          CROSS JOIN settings s

          WHERE q.id = $1
            AND s.id = 1
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Registro não encontrado.",
        });
      }

      const item = result.rows[0];

      let position = null;

      if (
        [
          "aguardando",
          "chamado",
        ].includes(item.status)
      ) {
        /*
         * Atualiza a posição pelo ID.
         * Mantém o mesmo cálculo do cadastro.
         */
        const positionResult =
          await pool.query(
            `
              SELECT
                COUNT(*)::int AS position

              FROM queue_entries q

              CROSS JOIN queue_entries target

              WHERE target.id = $1

                AND q.status IN (
                  'aguardando',
                  'chamado',
                  'balanca'
                )

                AND (
                  q.arrival_time,
                  q.id
                ) <= (
                  target.arrival_time,
                  target.id
                )
            `,
            [item.id]
          );

        position =
          positionResult.rows[0].position;
      }

      res.json({
        id: item.id,

        plate: item.plate,

        status: item.status,

        arrival_time:
          item.arrival_time,

        position,

        presenceRequired:
          Boolean(
            item.presence_required
          ),

        presence: presenceSnapshot(
          item,
          item.radius_m
        ),
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/admin/login",
  loginLimiter,
  (req, res) => {
    const password = String(
      req.body.password || ""
    );

    if (
      !safeCompare(
        password,
        ADMIN_PASSWORD
      )
    ) {
      return res.status(401).json({
        error: "Senha incorreta.",
      });
    }

    res.json({
      token: createAdminToken(),
      expiresInHours: 12,
    });
  }
);

app.get(
  "/api/admin/settings",
  requireAdmin,
  async (_req, res, next) => {
    try {
      const result = await pool.query(
        `
          SELECT
            unit_name,
            daily_code,
            latitude,
            longitude,
            radius_m,
            block_device,
            updated_at

          FROM settings

          WHERE id = 1
        `
      );

      res.json({
        ...result.rows[0],

        presence_interval_seconds:
          PRESENCE_INTERVAL_SECONDS,

        presence_stale_seconds:
          PRESENCE_STALE_SECONDS,

        presence_outside_grace_seconds:
          PRESENCE_OUTSIDE_GRACE_SECONDS,

        presence_max_accuracy_meters:
          PRESENCE_MAX_ACCURACY_METERS,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.put(
  "/api/admin/settings",
  requireAdmin,
  async (req, res, next) => {
    try {
      const unitName = cleanText(
        req.body.unitName,
        120
      );

      const dailyCode = cleanText(
        req.body.dailyCode,
        12
      );

      const latitude = Number(
        req.body.latitude
      );

      const longitude = Number(
        req.body.longitude
      );

      const radiusM = Number(
        req.body.radiusM
      );

      const blockDevice = Boolean(
        req.body.blockDevice
      );

      if (unitName.length < 2) {
        return res.status(400).json({
          error:
            "Nome da unidade inválido.",
        });
      }

      if (dailyCode.length < 3) {
        return res.status(400).json({
          error:
            "Código do dia inválido.",
        });
      }

      if (
        !isFiniteCoordinate(
          latitude,
          -90,
          90
        )
      ) {
        return res.status(400).json({
          error: "Latitude inválida.",
        });
      }

      if (
        !isFiniteCoordinate(
          longitude,
          -180,
          180
        )
      ) {
        return res.status(400).json({
          error: "Longitude inválida.",
        });
      }

      if (
        !Number.isInteger(radiusM) ||
        radiusM < 20 ||
        radiusM > 10000
      ) {
        return res.status(400).json({
          error:
            "O raio deve ficar entre 20 e 10.000 metros.",
        });
      }

      const result = await pool.query(
        `
          UPDATE settings

          SET
            unit_name = $1,
            daily_code = $2,
            latitude = $3,
            longitude = $4,
            radius_m = $5,
            block_device = $6,
            updated_at = NOW()

          WHERE id = 1

          RETURNING
            unit_name,
            daily_code,
            latitude,
            longitude,
            radius_m,
            block_device,
            updated_at
        `,
        [
          unitName,
          dailyCode,
          latitude,
          longitude,
          radiusM,
          blockDevice,
        ]
      );

      await audit(
        "SETTINGS_UPDATED",
        {
          unitName,
          radiusM,
          blockDevice,
        }
      );

      res.json(result.rows[0]);
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/admin/settings/new-code",
  requireAdmin,
  async (_req, res, next) => {
    try {
      const dailyCode = String(
        crypto.randomInt(
          1000,
          10000
        )
      );

      await pool.query(
        `
          UPDATE settings

          SET
            daily_code = $1,
            updated_at = NOW()

          WHERE id = 1
        `,
        [dailyCode]
      );

      await audit(
        "DAILY_CODE_CHANGED",
        {
          dailyCode,
        }
      );

      res.json({
        dailyCode,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/admin/queue",
  requireAdmin,
  async (_req, res, next) => {
    try {
      const settingsResult =
        await pool.query(
          `
            SELECT radius_m
            FROM settings
            WHERE id = 1
          `
        );

      const radius =
        settingsResult.rows[0].radius_m;

      const result = await pool.query(
        `
          SELECT
            id,
            plate,
            driver_name,
            carrier,
            status,
            arrival_time,
            updated_at,
            distance_m,
            latitude,
            longitude,
            manual,
            presence_required,
            last_presence_at,
            last_presence_latitude,
            last_presence_longitude,
            last_presence_distance_m,
            last_presence_accuracy_m,
            outside_since

          FROM queue_entries

          ORDER BY

            CASE
              WHEN status = 'finalizado'
              THEN 1
              ELSE 0
            END,

            arrival_time ASC,
            id ASC

          LIMIT 500
        `
      );

      res.json(
        result.rows.map((row) => ({
          ...row,

          presence: presenceSnapshot(
            row,
            radius
          ),
        }))
      );
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/admin/queue/manual",
  requireAdmin,
  async (req, res, next) => {
    try {
      const plate = normalizePlate(
        req.body.plate
      );

      const driverName = cleanText(
        req.body.driverName,
        120
      );

      const carrier = cleanText(
        req.body.carrier,
        160
      );

      if (!isValidPlate(plate)) {
        return res.status(400).json({
          error: "Placa inválida.",
        });
      }

      if (driverName.length < 3) {
        return res.status(400).json({
          error: "Motorista inválido.",
        });
      }

      if (carrier.length < 2) {
        return res.status(400).json({
          error:
            "Transportadora inválida.",
        });
      }

      const id = crypto.randomUUID();

      const result = await pool.query(
        `
          INSERT INTO queue_entries (
            id,
            plate,
            driver_name,
            carrier,
            manual,
            presence_required
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            TRUE,
            FALSE
          )
          RETURNING *
        `,
        [
          id,
          plate,
          driverName,
          carrier,
        ]
      );

      await audit(
        "MANUAL_QUEUE_CREATED",
        {
          id,
          plate,
        }
      );

      res.status(201).json(
        result.rows[0]
      );
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error:
            "Esta placa já está ativa na fila.",
        });
      }

      next(error);
    }
  }
);

app.patch(
  "/api/admin/queue/:id/status",
  requireAdmin,
  async (req, res, next) => {
    const client = await pool.connect();

    try {
      const allowed = new Set([
        "aguardando",
        "chamado",
        "balanca",
        "finalizado",
      ]);

      const status = String(
        req.body.status || ""
      );

      const forcePresence =
        req.body.forcePresence === true;

      if (!allowed.has(status)) {
        return res.status(400).json({
          error: "Situação inválida.",
        });
      }

      await client.query("BEGIN");

      const currentResult =
        await client.query(
          `
            SELECT
              q.*,
              s.radius_m

            FROM queue_entries q

            CROSS JOIN settings s

            WHERE q.id = $1
              AND s.id = 1

            FOR UPDATE OF q
          `,
          [req.params.id]
        );

      if (currentResult.rowCount === 0) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error:
            "Registro não encontrado.",
        });
      }

      const current =
        currentResult.rows[0];

      if (status === "chamado") {
        if (
          current.status !== "aguardando"
        ) {
          await client.query("ROLLBACK");

          return res.status(409).json({
            error:
              "Este motorista já foi chamado ou não está mais aguardando.",
          });
        }

        const presence =
          presenceSnapshot(
            current,
            current.radius_m
          );

        if (
          !presence.canCall &&
          !forcePresence
        ) {
          await client.query("ROLLBACK");

          return res.status(409).json({
            error:
              presence.blockReason,

            code:
              "PRESENCE_BLOCKED",

            presence,
          });
        }

        if (
          !presence.canCall &&
          forcePresence
        ) {
          await audit(
            "QUEUE_CALLED_WITH_PRESENCE_OVERRIDE",
            {
              id: current.id,

              plate: current.plate,

              presenceState:
                presence.state,

              reason:
                presence.blockReason,
            },
            client
          );
        }
      }

      const result = await client.query(
        `
          UPDATE queue_entries

          SET
            status = $1,
            updated_at = NOW()

          WHERE id = $2

          RETURNING *
        `,
        [
          status,
          req.params.id,
        ]
      );

      await audit(
        "QUEUE_STATUS_UPDATED",
        {
          id: req.params.id,
          status,
          forcePresence,
        },
        client
      );

      await client.query("COMMIT");

      res.json(result.rows[0]);
    } catch (error) {
      await client
        .query("ROLLBACK")
        .catch(() => {});

      next(error);
    } finally {
      client.release();
    }
  }
);

app.delete(
  "/api/admin/queue/:id",
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `
          DELETE FROM queue_entries

          WHERE id = $1

          RETURNING plate
        `,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error:
            "Registro não encontrado.",
        });
      }

      await audit(
        "QUEUE_DELETED",
        {
          id: req.params.id,

          plate:
            result.rows[0].plate,
        }
      );

      res.json({
        ok: true,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.delete(
  "/api/admin/queue",
  requireAdmin,
  async (req, res, next) => {
    try {
      const scope =
        req.query.scope === "finished"
          ? "finished"
          : "all";

      const result =
        scope === "finished"
          ? await pool.query(
              `
                DELETE FROM queue_entries

                WHERE status = 'finalizado'
              `
            )
          : await pool.query(
              `
                DELETE FROM queue_entries
              `
            );

      await audit(
        "QUEUE_CLEARED",
        {
          scope,

          count: result.rowCount,
        }
      );

      res.json({
        ok: true,

        deleted: result.rowCount,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    ),
    {
      extensions: ["html"],

      maxAge:
        process.env.NODE_ENV ===
        "production"
          ? "1h"
          : 0,
    }
  )
);

app.get(
  "/{*splat}",
  (_req, res) => {
    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

app.use(
  (error, req, res, _next) => {
    console.error("ERRO INTERNO:", {
      method: req.method,

      path: req.originalUrl,

      message: error.message,

      code: error.code,

      detail: error.detail,

      constraint: error.constraint,

      stack: error.stack,
    });

    res.status(500).json({
      error:
        "Erro interno do sistema.",
    });
  }
);

initDatabase()
  .then(() => {
    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Fila de carregamento V15.1.3 iniciada na porta ${PORT}.`
        );
      }
    );
  })
  .catch((error) => {
    console.error(
      "Falha ao preparar o banco de dados:",
      error
    );

    process.exit(1);
  });
