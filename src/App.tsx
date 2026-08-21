import { HashRouter, Link, NavLink, Route, Routes } from 'react-router-dom'
import { HomePage } from './pages/HomePage.tsx'
import { ImportPage } from './pages/ImportPage.tsx'
import { LessonPage } from './pages/LessonPage.tsx'

export function App() {
  return (
    <HashRouter>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <nav className="nav" aria-label="Primary">
        <Link className="nav-brand" to="/">
          PacketViz
        </Link>
        <NavLink to="/" end>
          Lessons
        </NavLink>
        <NavLink to="/import">Import</NavLink>
      </nav>

      <main id="main">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/lesson/:slug" element={<LessonPage />} />
          <Route path="/import" element={<ImportPage />} />
          <Route
            path="*"
            element={
              <div className="not-found">
                <h1>Nothing here</h1>
                <p>
                  <Link to="/">Back to the lessons</Link>
                </p>
              </div>
            }
          />
        </Routes>
      </main>
    </HashRouter>
  )
}
