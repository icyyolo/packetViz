/**
 * The last line of defence for imported files.
 *
 * `decodeFrame` and `readPcap` are total by contract and by fuzz test, so in
 * principle nothing here should ever fire. That is exactly why it exists: the
 * contract covers the decoder, not every line of rendering code that consumes
 * it, and a stranger's capture is the input most likely to find the gap. A
 * caught error becomes a message with a way out; without this, React 19
 * unmounts the whole tree and the visitor gets a white page.
 */

import { Component, type ErrorInfo, type ReactNode } from 'react'

export type ErrorBoundaryProps = {
  children: ReactNode
  /** Shown above the error text, e.g. "This capture could not be displayed." */
  title: string
  /** Rendered under the message: usually a way to load a different file. */
  action?: ReactNode
}

type ErrorBoundaryState = { error: Error | null }

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  override state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Kept in the console rather than on screen: the visitor gets the message,
    // and whoever is debugging gets the component stack.
    console.error('PacketViz caught a render error', error, info.componentStack)
  }

  override render(): ReactNode {
    const { error } = this.state
    if (error === null) return this.props.children

    return (
      <div className="import-error" role="alert">
        <h2>{this.props.title}</h2>
        <p>{error.message}</p>
        {this.props.action}
      </div>
    )
  }
}
