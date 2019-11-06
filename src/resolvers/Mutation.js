const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const stripe = require('../stripe');

const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');

const tokenMaxAge = 1000 * 60 * 60 * 24 * 365;

const Mutations = {
  async createItem(parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!');
    }
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // This is how we create relationship between item and user.
          user: {
            connect: {
              id: ctx.request.userId,
            },
          },
          ...args,
        },
      },
      info
    );

    return item;
  },

  updateItem(parent, args, ctx, info) {
    // first take a copy of the updates
    const updates = { ...args };
    // remove the id from the updates
    delete updates.id;
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id,
        },
      },
      info
    );
  },

  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // find item
    const item = await ctx.db.query.item({ where }, `{ id title user{ id }}`);
    // check if they own
    const ownsItem = item.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(permission =>
      ['ADMIN', 'ITEMDELETE'].includes(permission)
    );

    if (!ownsItem || !hasPermissions) {
      throw new Error('You do not have permission to do that!');
    }

    // Delete
    return ctx.db.mutation.deleteItem({ where }, info);
  },

  async signup(parent, args, ctx, info) {
    args.email = args.email.toLowerCase();
    // hash pass + salt
    const password = await bcrypt.hash(args.password, 10);
    // Create user in DB
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ['USER'] },
        },
      },
      info
    );

    // Create JWT + Sign in
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // Set jwt to cookie on response
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
    });

    return user;
  },

  async signin(parent, { email, password }, ctx, info) {
    // check if there is a user with email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    // check if password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error('Invalid Password');
    }
    // Generate jwt
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // Set the cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: tokenMaxAge,
    });
    // return user
    return user;
  },

  signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token');
    return { message: 'Goodbye!' };
  },

  async requestReset(parent, args, ctx, info) {
    // 1. Check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email } });

    if (!user) {
      throw new Error(`No user found for this email ${args.email}`);
    }
    // 2. Set a reset token and expiry
    const randomBytesPromise = promisify(randomBytes);
    const resetToken = (await randomBytesPromise(20)).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000;
    await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry },
    });
    // 3. Email them that reset token.
    const mailResponse = await transport.sendMail({
      from: 'vince@vincebrown.me',
      to: user.email,
      subject: 'Your password reset token',
      html: makeANiceEmail(
        `Your password Reset Token is here! \n\n <a href="${
          process.env.FRONTEND_URL
        }/reset?resetToken=${resetToken}">Reset Password</a>`
      ),
    });

    // Return the msg
    return { message: 'Password reset has been sent!' };
  },

  async resetPassword(parent, args, ctx, info) {
    // 1.) first check if passwords match
    if (args.newPassword !== args.confirmPassword) {
      throw new Error(`Please make sure your new password matches.`);
    }

    // 2.) check if it is a legit reset token
    // 3.) Check if it is expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000,
      },
    });

    if (!user) {
      throw new Error(`This token is either invalid or expired.`);
    }

    // 4.) Hash new password
    const hashedNewPassword = await bcrypt.hash(args.newPassword, 10);

    // 5.) save new password to user and remove old reset token fields
    const updatedUser = await ctx.db.mutation.updateUser(
      {
        data: {
          password: hashedNewPassword,
          resetToken: null,
          resetTokenExpiry: null,
        },
        where: {
          email: user.email,
        },
      },
      info
    );

    // 6.) Generate JWT
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);

    // 7.) set the JWT cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: tokenMaxAge,
    });
    // 8.) Return the new user.
    return updatedUser;
  },

  async updatePermissions(parent, args, ctx, info) {
    // Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error(`You must be logged in!`);
    }

    // Query the current user
    const currentUser = await ctx.db.query.user(
      {
        where: { id: ctx.request.userId },
      },
      info
    );

    // Check if they have permissions to update
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);

    // Update the permissions + return user
    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions,
          },
        },
        where: {
          id: args.userId,
        },
      },
      info
    );
  },

  async addToCart(parent, args, ctx, info) {
    // Make sure they are signed in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error('You must be signed in.');
    }
    // Query the users current cart
    const [exisitingCartItem] = await ctx.db.query.cartItems(
      {
        where: {
          user: { id: userId },
          item: { id: args.id },
        },
      },
      info
    );
    // check if that item is already in their cart.
    // if it is increment.
    if (exisitingCartItem) {
      return ctx.db.mutation.updateCartItem({
        where: { id: exisitingCartItem.id },
        data: { quantity: exisitingCartItem.quantity + 1 },
      });
    }
    // if not create item in cart
    return ctx.db.mutation.createCartItem(
      {
        data: {
          user: {
            connect: { id: userId },
          },
          item: {
            connect: { id: args.id },
          },
        },
      },
      info
    );
  },

  async removeFromCart(parent, args, ctx, info) {
    // 1. Find the cart item
    const cartItem = await ctx.db.query.cartItem(
      {
        where: { id: args.id },
      },
      `{id, user{id}}`
    );

    // Check if item exists.
    if (!cartItem) {
      throw new Error('Cart Item does not exist');
    }

    // 2. Make sure they own the cart item
    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error('You do not have permission to do this.');
    }

    // 3. Delete that item
    return ctx.db.mutation.deleteCartItem(
      {
        where: { id: args.id },
      },
      info
    );
  },

  async createOrder(parent, args, ctx, info) {
    // query the current user + confirm signed in.
    const { userId } = ctx.request;
    if (!userId) throw new Error('You must be signed in');
    const user = await ctx.db.query.user(
      {
        where: { id: userId },
      },
      `
      {
        id 
        name 
        email 
        cart { 
          id 
          quantity 
          item { 
            title 
            price 
            id 
            description 
            image
            largeImage
          }
        }
      }
    `
    );
    // recalc the total for the price.
    const amount = user.cart.reduce(
      (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    );
    // Create the Stripe Charge
    const charge = await stripe.charges.create({
      amount,
      currency: 'USD',
      source: args.token,
    });
    // Convert the CartItems to OrderItems

    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: { connect: { id: userId } },
      };
      delete orderItem.id;
      return orderItem;
    });
    // Create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        items: { create: orderItems },
        user: { connect: { id: userId } },
      },
    });
    // Clean the users cart, delete cart Items
    const cartItemIds = user.cart.map(cartItem => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemIds,
      },
    });
    // return the order to the client.
    return order;
  },
};

module.exports = Mutations;
