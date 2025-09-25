import { Request, Response, NextFunction } from 'express';
import InvoiceService from '../services/invoiceService';
import { Invoice } from '../types/invoice';

//funcion para evitar repetir la comprobación de userId en cada función
function checkInvoiceOwnership(invoice: Invoice, userId: number) {
  if (invoice.userId !== userId) {
    const err = new Error('Prohibido, no deberías poder acceder al recurso');
    (err as any).status = 403;
    throw err;
  }
}


const listInvoices = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const state = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;
    const userId = (req as any).user!.id; 

    const invoices = await InvoiceService.list(userId, state, operator);
    res.json(invoices);
  } catch (err) {
    next(err);
  }
};


const setPaymentCard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const { paymentBrand, ccNumber, ccv, expirationDate } = req.body;

    if (!paymentBrand || !ccNumber || !ccv || !expirationDate) {
      return res.status(400).json({ error: 'Missing payment details' });
    }

    const userId = (req as any).user!.id;
    const invoice = await InvoiceService.getInvoice(invoiceId);

    checkInvoiceOwnership(invoice, userId);

    await InvoiceService.setPaymentCard(userId, invoiceId, paymentBrand, ccNumber, ccv, expirationDate);
    res.status(200).json({ message: 'Payment successful' });
  } catch (err) {
    next(err);
  }
};

const getInvoicePDF = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const pdfName = req.query.pdfName as string | undefined;

    if (!pdfName) return res.status(400).json({ error: 'Missing parameter pdfName' });

    const userId = (req as any).user!.id;
    const invoice = await InvoiceService.getInvoice(invoiceId);

    checkInvoiceOwnership(invoice, userId);

    const pdf = await InvoiceService.getReceipt(invoiceId, pdfName);
    res.setHeader('Content-Type', 'application/pdf');
    res.send(pdf);
  } catch (err) {
    next(err);
  }
};


const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = req.params.id;
    const userId = (req as any).user!.id;

    const invoice = await InvoiceService.getInvoice(invoiceId);

    checkInvoiceOwnership(invoice, userId);

    res.status(200).json(invoice);
  } catch (err) {
    next(err);
  }
};

export default {
  listInvoices,
  setPaymentCard,
  getInvoice,
  getInvoicePDF
};
