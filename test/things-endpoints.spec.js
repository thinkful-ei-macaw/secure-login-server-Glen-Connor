const knex = require('knex')
const app = require('../src/app')
const helpers = require('./test-helpers')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

describe('Things Endpoints', function () {
  let db

  const {
    testUsers,
    testThings,
    testReviews,
  } = helpers.makeThingsFixtures()


  function makeAuthHeader(user, secret = process.env.JWT_SECRET) {

    const token = jwt.sign({ user_id: user.id }, secret, {
      subject: user.user_name,
      algorithm: 'HS256',
    })

    return `Bearer ${token}`

  }

  before('make knex instance', () => {
    db = knex({
      client: 'pg',
      connection: process.env.TEST_DB_URL,
    })
    app.set('db', db)
  })

  after('disconnect from db', () => db.destroy())

  before('cleanup', () => helpers.cleanTables(db))

  afterEach('cleanup', () => helpers.cleanTables(db))

  describe.only(`Protected endpoints`, () => {
    // this.beforeEach('insert things', () =>
    //   helpers.seedThingsTables(
    //     db,
    //     testUsers,
    //     testThings,
    //     testReviews
    //   )
    // )
    describe(`GET /api/things/:things_id`, () => {
      it(`responds with 401 'Missing basic token' when no basic token`, () => {
        const thingId = 1234
        return supertest(app)
          .get(`/api/things/1234`)
          .expect(401, { error: `Missing basic token` })

      })

    })
  })

  describe(`GET /api/things`, () => {
    context(`Given no things`, () => {
      it(`responds with 200 and an empty list`, () => {
        return supertest(app)
          .get('/api/things')
          .expect(200, [])
      })
    })

    context('Given there are things in the database', () => {
      beforeEach('insert things', () =>
        helpers.seedThingsTables(
          db,
          testUsers,
          testThings,
          testReviews,
        )
      )

      it('responds with 200 and all of the things', () => {
        const expectedThings = testThings.map(thing =>
          helpers.makeExpectedThing(
            testUsers,
            thing,
            testReviews,
          )
        )
        return supertest(app)
          .get('/api/things')
          .expect(200, expectedThings)
      })
    })

    context(`Given an XSS attack thing`, () => {
      const testUser = helpers.makeUsersArray()[1]
      const {
        maliciousThing,
        expectedThing,
      } = helpers.makeMaliciousThing(testUser)

      beforeEach('insert malicious thing', () => {
        return helpers.seedMaliciousThing(
          db,
          testUser,
          maliciousThing,
        )
      })

      it('removes XSS attack content', () => {
        return supertest(app)
          .get(`/api/things`)
          .set('Authorization', `basic ${makeAuthHeader(testUsers[0])}`)
          .expect(200)
          .expect(res => {
            expect(res.body[0].title).to.eql(expectedThing.title)
            expect(res.body[0].content).to.eql(expectedThing.content)
          })
      })
    })
  })

  describe.only(`GET /api/things/:thing_id`, () => {
    context(`Given no things`, () => {
      beforeEach(() =>
        helpers.seedUsers(db, testUsers))
      it(`responds with 404`, () => {
        const thingId = 123456

        return supertest(app)
          .get(`/api/things/${thingId}`)
          .set('Authorization', `basic ${makeAuthHeader(testUsers[0])}`)
          .expect(404, { error: `Thing doesn't exist` })
      })
    })

    context('Given there are things in the database', () => {
      beforeEach('insert things', () =>
        helpers.seedThingsTables(
          db,
          testUsers,
          testThings,
          testReviews,
        )
      )

      it('responds with 200 and the specified thing', () => {
        const thingId = 2
        const expectedThing = helpers.makeExpectedThing(
          testUsers,
          testThings[thingId - 1],
          testReviews,
        )

        return supertest(app)
          .get(`/api/things/${thingId}`)
          .set('Authorization', `basic ${makeAuthHeader(testUsers[0])}`)
          .expect(200, expectedThing)
      })
    })
    // helpers.makeUsersArray()[0]

    context(`Given an XSS attack thing`, () => {
      const testUser = testUsers[0]
      const {
        maliciousThing,
        expectedThing,
      } = helpers.makeMaliciousThing(testUser)

      beforeEach('insert malicious thing', () => {
        return helpers.seedMaliciousThing(
          db,
          testUser,
          maliciousThing,
        )
      })

      it.only('removes XSS attack content', () => {
        console.log(makeAuthHeader(testUsers[0]))
        return supertest(app)
          .get(`/api/things/${maliciousThing.id}`)
          .set('Authorization', `basic ${makeAuthHeader(testUsers[0])}`)
          .expect(200)
          .expect(res => {
            expect(res.body.title).to.eql(expectedThing.title)
            expect(res.body.content).to.eql(expectedThing.content)
          })

      })
    })
  })


  describe(`GET /api/things/:thing_id/reviews`, () => {
    context(`Given no things`, () => {
      beforeEach(() =>
        helpers.seedUsers(db, testUsers))
      it(`responds with 404`, () => {
        const thingId = 123456
        return supertest(app)
          .get(`/api/things/${thingId}/reviews`)
          .set('Authorization', `basic ${makeAuthHeader(testUsers[0])}`)
          .expect(404, { error: `Thing doesn't exist` })
      })
    })

    context('Given there are reviews for thing in the database', () => {
      beforeEach('insert things', () =>
        helpers.seedThingsTables(
          db,
          testUsers,
          testThings,
          testReviews,
        )
      )

      it('responds with 200 and the specified reviews', () => {
        const thingId = 1
        const expectedReviews = helpers.makeExpectedThingReviews(
          testUsers, thingId, testReviews
        )

        return supertest(app)
          .get(`/api/things/${thingId}/reviews`)
          .set('Authorization', `basic ${makeAuthHeader(testUsers[0])}`)
          .expect(200, expectedReviews)
      })
    })
  })
})

