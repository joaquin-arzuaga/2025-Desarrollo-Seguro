
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>

// mock the nodemailer module
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

// mock send email function
mockedNodemailer.createTransport = jest.fn().mockReturnValue({
  sendMail: jest.fn().mockResolvedValue({ success: true }),
});

describe('AuthService.templateInjection', () => {
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
  });

  /**
   * Test ÚNICO y EXCLUSIVO para TEMPLATE INJECTION
   * Centrado solo en los campos vulnerables: first_name y last_name.
   * Verifica que:
   *  - No se evalúan expresiones de plantillas (no debe aparecer "49" por 7*7).
   *  - No se inyectan scripts (<script> ... </script>).
   *  - Los marcadores de plantillas permanecen literales (o escapados) en el HTML del correo.
   */
  it('no evalua plantillas y preserva marcadores literales en first_name/last_name', async () => {
    // Marcadores típicos de motores de plantillas
    const markers = [
      '<%=7*7%>',   // EJS / ERB
      '{{7*7}}',    // Mustache / Handlebars
      '{% 7*7 %}',  // Jinja / Django
      '${7*7}',     // JS template literal
      '{{{7*7}}}',  // Handlebars triple-stash
    ];

    // Solo usar los campos vulnerables: first_name y last_name
    const user: User = {
      id: 'user-ti-1',
      email: 'victim@example.com',
      password: 'password123',
      first_name: markers.join(' | '),
      // incluye intento de script + más marcadores
      last_name: `<script>alert("x")</script> | ${markers.join(' | ')}`,
      username: 'safe-username',
    } as any;

    // Mock DB: no existe usuario previo, inserción OK
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis(),
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Ejecutar flujo que genera el correo
    await AuthService.createUser(user);

    // Capturar el HTML del mail
    expect(nodemailer.createTransport).toHaveBeenCalled();
    const sendMailMock = (nodemailer.createTransport() as any).sendMail;
    expect(sendMailMock).toHaveBeenCalled();
    const sendMailArg = sendMailMock.mock.calls[0][0];
    const html: string = (sendMailArg.html ?? '') as string;

    // Helper: HTML escape básico para comparar
    const escapeHtml = (s: string) =>
      s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');

    // 1) No debe aparecer el resultado de evaluar 7*7
    expect(html).not.toContain('49');

    // 2) No debe incluirse ningún <script> ni alert(...)
    const lower = html.toLowerCase();
    expect(lower).not.toContain('<script>');
    expect(lower).not.toContain('</script>');
    expect(html).not.toContain('alert(');

    // 3) Cada marcador debe aparecer literal o escapado en el HTML
    markers.forEach((m) => {
      const literal = m;
      const escaped = escapeHtml(m);
      const present = html.includes(literal) || html.includes(escaped);
      if (!present) {
        throw new Error(
          `El marcador no se encontró ni literal ni escapado en el HTML.\n` +
          `Marcador: ${literal}\n` +
          `Escaped:  ${escaped}\n` +
          `HTML (primeros 500 chars):\n${html.slice(0, 500)}`
        );
      }
    });

    // 4) El intento de script en last_name debe aparecer neutralizado (al menos escapado)
    const scriptLiteral = '<script>alert("x")</script>';
    const scriptEscaped = escapeHtml(scriptLiteral);
    // No literal crudo
    expect(html).not.toContain(scriptLiteral);
    // Permitimos que esté escapado o completamente ausente según la sanitización aplicada
    expect(html.includes(scriptEscaped) || !html.includes('alert("x")')).toBeTruthy();
  }, 20000);
});

/*
describe('AuthService.templateInjection', () => {
  const OLD_ENV = process.env;
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();

  });

  it('Template injection', async () => {
    const user = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: '<%= 7*7 %>{{ 7*7 }}',
      last_name: '<script>alert("x")</script>',
      username: 'username',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    // Verify the database calls
    expect(insertChain.insert).toHaveBeenCalledWith({
      email: user.email,
      password: expect.any(String),
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      activated: false,
      invite_token: expect.any(String),
      invite_token_expires: expect.any(Date)
    });

    expect(nodemailer.createTransport).toHaveBeenCalled();

    const sendMailArg = (nodemailer.createTransport() as any).sendMail.mock.calls[0][0];
    expect(sendMailArg).toBeDefined();
    const html = sendMailArg.html as string;

    expect(html).not.toEqual(expect.stringContaining('49'));

    expect(html).not.toEqual(expect.stringContaining('<script>'));
    expect(html).not.toEqual(expect.stringContaining('</script>'));

    expect(html).not.toEqual(expect.stringContaining('alert("x")'));

  }
  );

    it('Template injection - multiple template syntaxes remain literal (no evaluation)', async () => {
    // Create payloads that include many common template syntaxes
    const user = {
      id: 'user-456',
      email: 'templated+{{7*7}}@example.com',
      password: 'password123',
      first_name: '<%=7*7%>',
      // Handlebars / Mustache
      last_name: '{{7*7}}',
      // Django / Jinja style
      username: '{% 7*7 %}',
      // JS template literal style
      // note: this is intended to detect dangerous server-side eval, not client-side template strings
      // put it in another field (e.g., an optional field) or username2 — we'll reuse a fake field
      // Our User type may not include it, but the service likely uses object spreading; include as any
      // Using as any to avoid TS errors in tests
      // also include triple-stash variant
      // We'll add an extra display_name field for email/template rendering
      display_name: '${7*7}',
      bio: '{{{7*7}}}',
    } as any as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    const sendMailArg = (nodemailer.createTransport() as any).sendMail.mock.calls[0][0];
    const html = sendMailArg.html as string;
    const subject = sendMailArg.subject as string;

    // Important: ensure NOTHING was evaluated into '49'
    expect(html).not.toEqual(expect.stringContaining('49'));
    expect(subject).not.toEqual(expect.stringContaining('49'));

    // Also ensure that the literal template markers appear in the email body (escaped or shown),
    // which indicates the templates were NOT executed. We check for presence of the raw sequences we injected.
    // (Depending on how your template is escaped you might see them encoded — adapt if necessary.)
    expect(html).toEqual(expect.stringContaining('<%=7*7%>'));
    expect(html).toEqual(expect.stringContaining('{{7*7}}'));
    expect(html).toEqual(expect.stringContaining('{% 7*7 %}'));
    expect(html).toEqual(expect.stringContaining('${7*7}'));
    expect(html).toEqual(expect.stringContaining('{{{7*7}}}'));
  });

  it('Template injection - subject and href should not contain evaluated results', async () => {
    // This test ensures that template payloads in username/email do NOT cause evaluation
    const user = {
      id: 'user-789',
      email: 'user-<%= 7*7 %>@example.com',
      password: 'password123',
      first_name: 'Normal',
      last_name: 'User',
      username: 'user-{{7*7}}',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    const sendMailArg = (nodemailer.createTransport() as any).sendMail.mock.calls[0][0];
    expect(sendMailArg).toBeDefined();

    const html = sendMailArg.html as string;
    const to = sendMailArg.to as string;
    const subject = sendMailArg.subject as string;

    // The "to" should be the literal email we passed (or sanitized), but should NOT include evaluated values like '49'
    expect(to).toEqual(expect.stringContaining('<%= 7*7 %>') || expect.stringContaining('user-'));
    expect(to).not.toEqual(expect.stringContaining('49'));

    // Subject must not contain evaluated results
    expect(subject).not.toEqual(expect.stringContaining('49'));

    // Email body (html) must NOT include evaluated '49' and must not contain script tags
    expect(html).not.toEqual(expect.stringContaining('49'));
    expect(html).not.toEqual(expect.stringContaining('<script>'));
    expect(html).not.toEqual(expect.stringContaining('</script>'));

    // And the literal template markers used in username/email should appear somewhere in the email body (escaped),
    // giving confidence that injection was not executed.
    expect(html).toEqual(expect.stringContaining('<%= 7*7 %>') || expect.stringContaining('{"user-'));
    expect(html).toEqual(expect.stringContaining('{{7*7}}') || expect.stringContaining('user-'));
  });

  */
  /*
  it('createUser', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
    .mockReturnValueOnce(selectChain as any)
    .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    // Verify the database calls
    expect(insertChain.insert).toHaveBeenCalledWith({
      email: user.email,
      password: user.password,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      activated: false,
      invite_token: expect.any(String),
      invite_token_expires: expect.any(Date)
    });

    expect(nodemailer.createTransport).toHaveBeenCalled();
    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith({
      to: user.email,
      subject: 'Activate your account',
      html: expect.stringContaining('Click <a href="')
    });
  }
  );

  it('createUser already exist', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;
    // mock user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(user) // Existing user found
    };
    mockedDb.mockReturnValueOnce(selectChain as any);
    // Call the method to test
    await expect(AuthService.createUser(user)).rejects.toThrow('User already exists with that username or email');
  });

  it('updateUser', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@b.com',
      password: 'newpassword123',
      first_name: 'NewFirst',
      last_name: 'NewLast',
      username: 'newusername',
    } as User;
    // mock user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({ id: user.id }) // Existing user found
    };
    // Mock the database update
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(user) // Update successful
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(updateChain as any);
    // Call the method to test
    const updatedUser = await AuthService.updateUser(user);
    // Verify the database calls
    expect(selectChain.where).toHaveBeenCalledWith({ id: user.id });
    expect(updateChain.update).toHaveBeenCalled();
  });

  it('updateUser not found', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;
    // mock user not found
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user found
    };
    mockedDb.mockReturnValueOnce(selectChain as any);
    // Call the method to test
    await expect(AuthService.updateUser(user)).rejects.toThrow('User not found');
  });

  it('authenticate', async () => {
    const email = 'username';
    const password = 'password123';

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({password}),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    const user = await AuthService.authenticate(email, password);
    expect(getUserChain.where).toHaveBeenCalledWith({email : 'username'});
    expect(user).toBeDefined();
  });

  it('authenticate wrong pass', async () => {

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({password:'otherpassword'}),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid password');
  });

  it('authenticate wrong user', async () => {

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid email or not activated');
  });

  it('sendResetPasswordEmail', async () => {
    const email = 'a@a.com';
    const user = {
      id: 'user-123',
      email: email,
    };
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(user),
    };
    // Mock the database update password
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(1)
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any); 
    // Call the method to test
    await AuthService.sendResetPasswordEmail(email);
    expect(getUserChain.where).toHaveBeenCalledWith({ email });
    expect(updateChain.update).toHaveBeenCalledWith({
      reset_password_token: expect.any(String),
      reset_password_expires: expect.any(Date)
    });
    expect(mockedNodemailer.createTransport).toHaveBeenCalled();
    expect(mockedNodemailer.createTransport().sendMail).toHaveBeenCalledWith({
      to: user.email,
      subject: 'Your password reset link',
      html: expect.stringContaining('Click <a href="')
    });
  });

  it('sendResetPasswordEmail no mail', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };

    mockedDb
      .mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.sendResetPasswordEmail('a@a.com')).rejects.toThrow('No user with that email or not activated');
  });

  it('resetPassword', async () => {
    const token = 'valid-token';
    const newPassword = 'newpassword123';    
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({id: 'user-123'}),
    };
    // Mock the database update password
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(1)
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any);
    // Call the method to test
    await AuthService.resetPassword(token, newPassword);
    expect(getUserChain.where).toHaveBeenCalledWith('reset_password_token', token);
    expect(updateChain.update).toHaveBeenCalledWith({
      password: newPassword,
      reset_password_token: null,
      reset_password_expires: null
    });
  });

  it('resetPassword invalid token', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any);
    // Call the method to test
    await expect(AuthService.resetPassword('invalid-token', 'newpassword123')).rejects.toThrow('Invalid or expired reset token');
  });

  it('setInitialPassword', async () => {
    const password = 'whatawonderfulpassword';
    const user_id = 'user-123';
    const token = 'invite-token';
    // Mock the database row
    const mockRow = {
      id: user_id,
      invite_token: token,
      invite_token_expires: new Date(Date.now() + 1000 * 60 * 60 * 24) // 1 day from now
    };

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(mockRow),
    };

    // mock the database update password
    const updateChain = {
      where: jest.fn().mockResolvedValue(1),
      update: jest.fn().mockReturnThis()
    }

    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any);

    // Call the method to test
    await AuthService.setPassword(token, password);

    // Verify the database calls
    expect(updateChain.update).toHaveBeenCalledWith({
      password: password,
      invite_token: null,
      invite_token_expires: null
    });

    expect(updateChain.where).toHaveBeenCalledWith({ id: user_id });
  });

  it('setInitialPassword invalid token', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any);
    // Call the method to test
    await expect(AuthService.setPassword('invalid-token', 'newpassword123')).rejects.toThrow('Invalid or expired invite token');
  });

  it('generateJwt', () => {
    const userId = 'abcd-1234';
    const token = AuthService.generateJwt(userId);

    // token should be a non-empty string
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);

    // verify the token decodes to our payload
    const decoded = jwt.verify(token,"secreto_super_seguro");
    expect((decoded as any).id).toBe(userId);
  });
  */
});
