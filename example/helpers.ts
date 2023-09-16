import crypto from 'crypto';

export function generateToken(INVITE_TOKEN_SECRET: any) {
    const randomData = crypto.randomBytes(4).toString('hex');
    const fullSignature = crypto.createHmac('sha256', INVITE_TOKEN_SECRET || 'supersecret').update(randomData).digest('base64');
    
    // Truncate the signature to 16 bytes (before URL-safe encoding)
    const truncatedSignature = Buffer.from(fullSignature, 'base64').slice(0, 16).toString('base64');
    
    // Convert to URL-safe format
    const urlSafeSignature = truncatedSignature.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    return `${randomData}.${urlSafeSignature}`;
  }
  
export function verifyToken(INVITE_TOKEN_SECRET: any, token: any) {
    const [data, providedSignature] = token.split('.');
    
    const actualSignature = crypto.createHmac('sha256', INVITE_TOKEN_SECRET || 'supersecret').update(data).digest('base64');
    const urlSafeActualSignature = actualSignature.replace('+', '-').replace('/', '_').replace(/=+$/, '');
    
    return urlSafeActualSignature === providedSignature;
  }