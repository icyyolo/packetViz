import { useEffect, useMemo } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { findLesson } from '../lessons/index.ts'
import { compileScenario } from '../scenario/compile.ts'
import { useVirtualClock } from '../timeline/useTimeline.ts'
import { LessonShell } from '../ui/LessonShell.tsx'
import { SelectionUrlSync } from '../ui/SelectionUrlSync.tsx'
import { SelectionProvider } from '../views/SelectionContext.tsx'

export function LessonPage() {
  const { slug } = useParams<{ slug: string }>()
  const lesson = findLesson(slug)

  if (lesson === undefined) {
    return (
      <div className="not-found">
        <h1>No lesson called “{slug}”</h1>
        <p>
          It may not be built yet. <Link to="/">Back to the lessons</Link>.
        </p>
      </div>
    )
  }

  return <LoadedLesson key={lesson.slug} lesson={lesson} />
}

function LoadedLesson({ lesson }: { lesson: NonNullable<ReturnType<typeof findLesson>> }) {
  const [searchParams] = useSearchParams()
  const timeline = useMemo(() => compileScenario(lesson.scenario), [lesson])
  const clock = useVirtualClock(timeline.durationMs)

  const initialPacket = Number.parseInt(searchParams.get('p') ?? '', 10)
  const initialFieldId = searchParams.get('f')

  // A deep link restores the scrubber too, so the shared view matches the sender's.
  useEffect(() => {
    if (!Number.isInteger(initialPacket)) return
    const mark = timeline.marks[initialPacket]
    if (mark !== undefined) clock.seek(mark.arrivedMs)
    // Only on mount: later changes to `p` come from the user's own clicks.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <SelectionProvider
      packetCount={timeline.packets.length}
      initialPacketIndex={Number.isInteger(initialPacket) ? initialPacket : 0}
      initialFieldId={initialFieldId}
    >
      <SelectionUrlSync />
      <LessonShell
        title={lesson.title}
        blurb={lesson.blurb}
        timeline={timeline}
        narration={lesson.narration}
        filename={lesson.filename}
        clock={clock}
      />
    </SelectionProvider>
  )
}
