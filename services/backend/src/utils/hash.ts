// Metodos para el hasheo no reversible de contraseñas
import bcrypt from "bcrypt";

const DEFAULT_COST = Number(process.env.BCRYPT_COST ?? 12);

/** Hashea un registro*/
export async function hash(plain: string, cost = DEFAULT_COST): Promise<string> {
  if (!plain || plain.length < 8) {
    throw new Error("Password too short");
  }
  return bcrypt.hash(plain, cost);
}

/** Verifica si un texto plano coincide con el hash almacenado. */
export async function verifyHash(plain: string, hash: string): Promise<boolean> {
  return bcrypt.compare(plain, hash);
}


export function looksLikeBcryptHash(value: string): boolean {
  return /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(value);
}
