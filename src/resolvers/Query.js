const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils');

const Query = {
  items: forwardTo('db'),
  item: forwardTo('db'),
  itemsConnection: forwardTo('db'),
  me(parent, args, ctx, info) {
    // check if there is a current userId
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user(
      {
        where: { id: ctx.request.userId },
      },
      info
    );
  },
  async users(parent, args, ctx, info) {
    // Check if they are logged in.
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }

    // Check if the user has permission to query all users
    hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);

    // If they do, query all users.
    return ctx.db.query.users({}, info);
  },

  async order(parent, args, ctx, info) {
    // logged in
    if (!ctx.request.userId) {
      throw new Error('You are not logged in');
    }
    // query current order
    const order = await ctx.db.query.order(
      {
        where: { id: args.id },
      },
      info
    );
    // check if they have permissions to see order
    const ownsOrder = order.user.id === ctx.request.userId;
    const hasPermissionToSeeOrder = ctx.request.user.permissions.includes(
      'ADMIN'
    );

    if (!ownsOrder || !hasPermissionToSeeOrder) {
      throw new Error('Cant see this!');
    }

    // return the order
    return order;
  },

  async orders(parent, args, ctx, info) {
    // check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You are not logged in');
    }
    // Get all orders
    const orders = await ctx.db.query.orders(
      {
        where: {
          user: { id: ctx.request.userId },
        },
      },
      info
    );
    // check permissions to see orders
    return orders;
  },
};

module.exports = Query;
